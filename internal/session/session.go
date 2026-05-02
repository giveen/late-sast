package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"late/internal/client"
	"late/internal/common"
	"late/internal/debug"
	"late/internal/tool"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var shellExitCodeRe = regexp.MustCompile(`^Command failed with exit code\s+(-?\d+)`)

const (
	historyRecentWindow               = 8
	historyToolContentMaxCharsRecent  = 4000
	historyToolContentMaxCharsOlder   = 1200
	historyReasoningMaxCharsRecent    = 1200
	historyReasoningMaxCharsOlder     = 0
	historyCompactionMarkerOverhead   = 64
)

// Session manages the chat state and interacts with the LLM client.
type Session struct {
	client       *client.Client
	HistoryPath  string
	History      []client.ChatMessage
	systemPrompt string
	useTools     bool
	maxTokens    int
	extraBody    map[string]any
	Registry     *tool.Registry
	debugLogger  *debug.Logger
}

func New(c *client.Client, historyPath string, history []client.ChatMessage, systemPrompt string, useTools bool) *Session {
	return &Session{
		client:       c,
		HistoryPath:  historyPath,
		History:      history,
		systemPrompt: systemPrompt,
		useTools:     useTools,
		Registry:     tool.NewRegistry(),
	}
}

// SetMaxTokens sets the max_tokens for generation on this session.
// Zero means use the server default. Negative values are clamped to zero.
func (s *Session) SetMaxTokens(n int) {
	if n < 0 {
		n = 0
	}
	s.maxTokens = n
}

// SetExtraBody sets key-value pairs that are merged into every request's
// extra_body (flattened to the root by marshalFlattened). Useful for
// model-specific sampling parameters such as repeat_penalty.
func (s *Session) SetExtraBody(extra map[string]any) {
	s.extraBody = extra
}

// SetDebugLogger sets the debug logger for this session.
func (s *Session) SetDebugLogger(logger *debug.Logger) {
	s.debugLogger = logger
}

// ExecuteTool executes a tool call and returns the response as a string.
func (s *Session) ExecuteTool(ctx context.Context, tc client.ToolCall) (string, error) {
	started := time.Now()

	// Log tool call if debug logging is enabled
	if s.debugLogger != nil && s.debugLogger.Enabled() {
		s.debugLogger.LogToolCall(tc.Function.Name, json.RawMessage(tc.Function.Arguments))
	}

	// First check registry
	t := s.Registry.Get(tc.Function.Name)
	if t == nil {
		return "", fmt.Errorf("tool not found: %s", tc.Function.Name)
	}
	result, err := t.Execute(ctx, json.RawMessage(tc.Function.Arguments))

	// Log tool result if debug logging is enabled
	if s.debugLogger != nil && s.debugLogger.Enabled() {
		meta := classifyToolResult(tc.Function.Name, result, err, time.Since(started))
		s.debugLogger.LogToolResultWithMeta(tc.Function.Name, tc.ID, result, &meta)
	}

	return result, err
}

func classifyToolResult(toolName, result string, execErr error, duration time.Duration) debug.ToolResultMeta {
	meta := debug.ToolResultMeta{
		DurationMS:  duration.Milliseconds(),
		Status:      "success",
		OutputBytes: len(result),
	}

	if errors.Is(execErr, context.DeadlineExceeded) {
		meta.Status = "timeout"
		meta.Classification = "tool_timeout"
		return meta
	}
	if errors.Is(execErr, context.Canceled) {
		meta.Status = "cancelled"
		meta.Classification = "tool_cancelled"
		return meta
	}
	if execErr != nil {
		meta.Status = "failed"
		meta.Classification = "tool_error"
		return meta
	}

	if strings.Contains(result, "requires explicit approval") || strings.Contains(result, "Tool execution cancelled by user") {
		meta.Status = "blocked"
		meta.Classification = "policy_blocked"
		return meta
	}

	if toolName == "bash" {
		if strings.HasPrefix(result, "Command timed out after") {
			meta.Status = "timeout"
			meta.Classification = "shell_timeout"
			return meta
		}
		if strings.HasPrefix(result, "Command cancelled") {
			meta.Status = "cancelled"
			meta.Classification = "shell_cancelled"
			return meta
		}
		if matches := shellExitCodeRe.FindStringSubmatch(result); len(matches) == 2 {
			meta.Status = "failed"
			meta.Classification = "shell_exit_nonzero"
			if code, err := strconv.Atoi(matches[1]); err == nil {
				meta.ExitCode = &code
			}
			return meta
		}
		if strings.HasPrefix(result, "Error executing command:") {
			meta.Status = "failed"
			meta.Classification = "shell_runtime_error"
			return meta
		}
	}

	meta.Classification = "ok"
	return meta
}

// LogTurnSummary emits a turn-level summary event when debug logging is enabled.
func (s *Session) LogTurnSummary(summary debug.TurnSummary) {
	if s.debugLogger != nil && s.debugLogger.Enabled() {
		s.debugLogger.LogTurnSummary(summary)
	}
}

// AddToolResultMessage adds a tool response message to history.
func (s *Session) AddToolResultMessage(toolCallID, content string) error {
	s.History = append(s.History, client.ChatMessage{
		Role:       "tool",
		ToolCallID: toolCallID,
		Content:    content,
	})
	return s.saveAndNotify()
}

// AddAssistantMessageWithTools adds an assistant message with tool calls.
func (s *Session) AddAssistantMessageWithTools(content string, reasoning string, toolCalls []client.ToolCall) error {
	// Filter out tool calls with invalid JSON arguments and log them
	var validCalls []client.ToolCall
	for _, tc := range toolCalls {
		// Validate that arguments are parseable JSON
		if !json.Valid([]byte(tc.Function.Arguments)) {
			if s.debugLogger != nil && s.debugLogger.Enabled() {
				preview := tc.Function.Arguments
				if len(preview) > 100 {
					preview = preview[:100] + "..."
				}
				s.debugLogger.LogEvent("MALFORMED_TOOL_CALL", fmt.Sprintf("Skipping tool call %q: invalid JSON arguments", tc.Function.Name),
					map[string]interface{}{"tool": tc.Function.Name, "arguments_preview": preview})
			}
			continue
		}
		validCalls = append(validCalls, tc)
	}

	s.History = append(s.History, client.ChatMessage{
		Role:             "assistant",
		Content:          content,
		ReasoningContent: reasoning,
		ToolCalls:        validCalls,
	})
	return s.saveAndNotify()
}

func (s *Session) GetToolDefinitions() []client.ToolDefinition {
	var defs []client.ToolDefinition
	for _, t := range s.Registry.All() {
		// Skip bash tool if disabled is handled by registry being empty of it
		defs = append(defs, client.ToolDefinition{
			Type: "function",
			Function: client.FunctionDefinition{
				Name:        t.Name(),
				Description: t.Description(),
				Parameters:  t.Parameters(),
			},
		})
	}
	return defs
}

// AddUserMessage adds a user message to history and persists it.
func (s *Session) AddUserMessage(content string) error {
	s.History = append(s.History, client.ChatMessage{Role: "user", Content: content})
	return s.saveAndNotify()
}

// AddAssistantMessage adds an assistant message to history and persists it.
func (s *Session) AddAssistantMessage(content, reasoning string) error {
	s.History = append(s.History, client.ChatMessage{
		Role:             "assistant",
		Content:          content,
		ReasoningContent: reasoning,
	})
	return s.saveAndNotify()
}

// AppendToLastMessage appends content to the last message (continuation).
func (s *Session) AppendToLastMessage(content, reasoning string) error {
	if len(s.History) == 0 {
		return fmt.Errorf("no history to append to")
	}
	lastIdx := len(s.History) - 1
	s.History[lastIdx].Content += content
	if reasoning != "" {
		if s.History[lastIdx].ReasoningContent != "" {
			s.History[lastIdx].ReasoningContent += "\n" + reasoning
		} else {
			s.History[lastIdx].ReasoningContent = reasoning
		}
	}
	return s.saveAndNotify()
}

// StartStream initiates a streaming response.
// It returns a standard Go channel for results and error.
func (s *Session) StartStream(ctx context.Context, extraBody map[string]any) (<-chan common.StreamResult, <-chan error) {
	outCh := make(chan common.StreamResult)
	errCh := make(chan error, 1)

	// Prepare messages with system prompt
	messages := make([]client.ChatMessage, 0, len(s.History)+1)
	if s.systemPrompt != "" {
		messages = append(messages, client.ChatMessage{Role: "system", Content: s.systemPrompt})
	}
	messages = append(messages, s.History...)

	mergedExtra := extraBody
	if len(s.extraBody) > 0 {
		mergedExtra = make(map[string]any, len(s.extraBody)+len(extraBody))
		for k, v := range s.extraBody {
			mergedExtra[k] = v
		}
		// Caller-supplied values take precedence
		for k, v := range extraBody {
			mergedExtra[k] = v
		}
	}

	req := client.ChatCompletionRequest{
		Messages:  messages,
		MaxTokens: s.maxTokens,
		ExtraBody: mergedExtra,
	}

	if s.useTools {
		req.Tools = s.GetToolDefinitions()
	}

	// Log the outgoing LLM request
	if s.debugLogger != nil && s.debugLogger.Enabled() {
		toolNames := make([]string, 0, len(req.Tools))
		for _, t := range req.Tools {
			toolNames = append(toolNames, t.Function.Name)
		}
		s.debugLogger.LogEvent("LLM_REQUEST", "Sending request to LLM", map[string]interface{}{
			"model":       s.client.Model(),
			"base_url":    s.client.BaseURL(),
			"history_len": len(s.History),
			"tools":       toolNames,
			"max_tokens":  s.maxTokens,
		})
	}

	streamOut, streamErr := s.client.ChatCompletionStream(ctx, req)

	go func() {
		defer close(outCh)
		defer close(errCh)

		for {
			select {
			case chunk, ok := <-streamOut:
				if !ok {
					return
				}
				var content, reasoning, finishReason string
				var toolCalls []client.ToolCall
				if len(chunk.Choices) > 0 {
					content = chunk.Choices[0].Delta.Content
					reasoning = chunk.Choices[0].Delta.ReasoningContent
					toolCalls = chunk.Choices[0].Delta.ToolCalls
					finishReason = chunk.Choices[0].FinishReason
				}

				res := common.StreamResult{
					Content:          content,
					ReasoningContent: reasoning,
					ToolCalls:        toolCalls,
					Usage:            chunk.Usage,
					FinishReason:     finishReason,
				}

				select {
				case outCh <- res:
				case <-ctx.Done():
					return
				}

			case err, ok := <-streamErr:
				if !ok {
					return
				}
				select {
				case errCh <- err:
				case <-ctx.Done():
					return
				}
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return outCh, errCh
}

// Impersonate returns a raw completion suggestion using the legacy format.
func (s *Session) Impersonate(ctx context.Context) (string, error) {
	var sb strings.Builder
	for _, msg := range s.History {
		sb.WriteString(fmt.Sprintf("%s\n%s\n", msg.Role, msg.Content))
	}
	prompt := sb.String() + "user\n"

	req := client.CompletionRequest{
		Prompt:    prompt,
		Stop:      []string{"\n", ""},
		N_Predict: 50,
	}

	resp, err := s.client.Completion(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// GenerateSessionMeta creates metadata from session state
func (s *Session) GenerateSessionMeta() SessionMeta {
	title := "Untitled Session"
	lastPrompt := ""

	if len(s.History) > 0 {
		// Find first user message for title
		for _, msg := range s.History {
			if msg.Role == "user" && title == "Untitled Session" {
				truncated := msg.Content
				if len(truncated) > 100 {
					truncated = truncateUTF8(truncated, 100)
				}
				title = truncated
				break
			}
		}
		// Last user message for last prompt
		for i := len(s.History) - 1; i >= 0; i-- {
			if s.History[i].Role == "user" {
				lastPrompt = s.History[i].Content
				if len(lastPrompt) > 50 {
					lastPrompt = truncateUTF8(lastPrompt, 50)
				}
				break
			}
		}
	}

	id := filepath.Base(s.HistoryPath)
	id = strings.TrimSuffix(id, ".json")

	return SessionMeta{
		ID:             id,
		Title:          title,
		CreatedAt:      time.Now(),
		LastUpdated:    time.Now(),
		HistoryPath:    s.HistoryPath,
		LastUserPrompt: lastPrompt,
		MessageCount:   len(s.History),
	}
}

// UpdateSessionMetadata updates the session metadata file
func (s *Session) UpdateSessionMetadata() error {
	meta := s.GenerateSessionMeta()
	return SaveSessionMeta(meta)
}

// SystemPrompt returns the system prompt for this session
func (s *Session) SystemPrompt() string {
	return s.systemPrompt
}

func (s *Session) saveAndNotify() error {
	if len(s.History) == 0 {
		return nil
	}
	compactHistoryForContext(s.History)
	if s.HistoryPath == "" {
		return nil // Skip saving if no path provided (e.g., subagents)
	}
	if err := SaveHistory(s.HistoryPath, s.History); err != nil {
		return err
	}
	return s.UpdateSessionMetadata()
}

func (s *Session) Client() *client.Client {
	return s.client
}

func (s *Session) IsLlamaCPP() bool {
	return s.client.IsLlamaCPP()
}

func compactHistoryForContext(history []client.ChatMessage) {
	if len(history) == 0 {
		return
	}

	recentStart := len(history) - historyRecentWindow
	if recentStart < 0 {
		recentStart = 0
	}

	for i := range history {
		isRecent := i >= recentStart
		switch history[i].Role {
		case "tool":
			limit := historyToolContentMaxCharsOlder
			if isRecent {
				limit = historyToolContentMaxCharsRecent
			}
			history[i].Content = compactHistoryText(history[i].Content, limit)
		case "assistant":
			limit := historyReasoningMaxCharsOlder
			if isRecent {
				limit = historyReasoningMaxCharsRecent
			}
			history[i].ReasoningContent = compactHistoryText(history[i].ReasoningContent, limit)
		}
	}
}

func compactHistoryText(text string, maxChars int) string {
	if maxChars <= 0 {
		return ""
	}
	if len(text) <= maxChars {
		return text
	}

	marker := fmt.Sprintf("\n... (history compacted, omitted %d chars)\n", len(text)-maxChars)
	available := maxChars - len(marker)
	if available <= 16 {
		if len(marker) > maxChars {
			return marker[:maxChars]
		}
		return marker
	}

	head := (available * 2) / 3
	tail := available - head
	if tail < 16 {
		tail = 16
		head = available - tail
	}
	if head < 16 {
		head = 16
		tail = available - head
	}

	return text[:head] + marker + text[len(text)-tail:]
}
