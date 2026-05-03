package session

import (
	"strings"
	"testing"

	"late/internal/client"
)

func TestCompactHistoryText_PreservesHeadAndTail(t *testing.T) {
	input := strings.Repeat("A", 80) + strings.Repeat("B", 80)
	got := compactHistoryText(input, 90)

	if len(got) > 90 {
		t.Fatalf("expected compacted text length <= 90, got %d", len(got))
	}
	if !strings.Contains(got, "history compacted") {
		t.Fatalf("expected compaction marker in output: %q", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("A", 16)) {
		t.Fatalf("expected head of original text to be preserved: %q", got)
	}
	if !strings.HasSuffix(got, strings.Repeat("B", 16)) {
		t.Fatalf("expected tail of original text to be preserved: %q", got)
	}
}

// ---------------------------------------------------------------------------
// collapseConsumedToolOutputs
// ---------------------------------------------------------------------------

func TestCollapseConsumedToolOutputs_ReplacesConsumedOlderMessages(t *testing.T) {
	// Arrange: 12 messages.  Indices 0-3 are older tool+assistant pairs;
	// indices 4-11 are the recent window (historyRecentWindow=8).
	toolCallID := "call-abc"
	bigOutput := strings.Repeat("X", 10000)

	history := []client.ChatMessage{
		// index 0: assistant decides to call a tool
		{Role: "assistant", ToolCalls: []client.ToolCall{
			{ID: toolCallID, Function: client.FunctionCall{Name: "bash", Arguments: `{"command":"ls"}`}},
		}},
		// index 1: tool result (older, consumed)
		{Role: "tool", ToolCallID: toolCallID, Content: bigOutput},
		// index 2: assistant follow-up — marks index 1 as consumed
		{Role: "assistant", Content: "done"},
		// indices 3-11: filler to push 0-2 outside recent window
	}
	for i := 0; i < 9; i++ {
		history = append(history, client.ChatMessage{Role: "user", Content: "ping"})
	}

	collapseConsumedToolOutputs(history)

	got := history[1].Content
	if !strings.HasPrefix(got, consumedPrefix) {
		t.Fatalf("expected content to start with %q, got: %q", consumedPrefix, got[:min(80, len(got))])
	}
	if len(got) >= len(bigOutput) {
		t.Fatalf("expected content to be compacted, got len=%d (original=%d)", len(got), len(bigOutput))
	}
	if !strings.Contains(got, "bash") {
		t.Fatalf("expected tool name 'bash' in summary, got: %q", got)
	}
	if !strings.Contains(got, "10000 chars") {
		t.Fatalf("expected original length in summary, got: %q", got)
	}
}

func TestCollapseConsumedToolOutputs_LeavesRecentWindowUntouched(t *testing.T) {
	toolCallID := "call-recent"
	bigOutput := strings.Repeat("Y", 8000)
	history := []client.ChatMessage{
		{Role: "assistant", ToolCalls: []client.ToolCall{
			{ID: toolCallID, Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"/foo"}`}},
		}},
		{Role: "tool", ToolCallID: toolCallID, Content: bigOutput},
		{Role: "assistant", Content: "I read the file"},
	}
	// Only 3 messages — all inside recentStart (< historyRecentWindow).
	collapseConsumedToolOutputs(history)

	if history[1].Content != bigOutput {
		t.Fatalf("expected recent tool content to be untouched, got len=%d", len(history[1].Content))
	}
}

func TestCollapseConsumedToolOutputs_KeepsFailureVerbose(t *testing.T) {
	toolCallID := "call-fail"
	errorOutput := "Command failed with exit code 1\n" + strings.Repeat("E", 2000)
	history := buildHistoryWithOlderToolResult(toolCallID, "bash", errorOutput, 10)

	collapseConsumedToolOutputs(history)

	got := history[1].Content
	if !strings.HasPrefix(got, consumedPrefix) {
		t.Fatalf("expected consumed prefix, got: %q", got[:min(80, len(got))])
	}
	if !strings.Contains(got, "failed") {
		t.Fatalf("expected 'failed' status in summary, got: %q", got[:min(200, len(got))])
	}
	// Failure excerpt should be longer than success excerpt.
	if len(got) < historyConsumedExcerptOK {
		t.Fatalf("expected failure summary to be longer than %d chars, got %d", historyConsumedExcerptOK, len(got))
	}
}

func TestCollapseConsumedToolOutputs_NeverReCompacts(t *testing.T) {
	alreadySummarised := consumedPrefix + " bash: ok, 5000 chars\nsome excerpt"
	toolCallID := "call-idempotent"
	history := buildHistoryWithOlderToolResult(toolCallID, "bash", alreadySummarised, 10)

	collapseConsumedToolOutputs(history)

	if history[1].Content != alreadySummarised {
		t.Fatalf("expected already-summarised content to be unchanged, got: %q", history[1].Content)
	}
}

func TestCollapseConsumedToolOutputs_LeavesUnconsumedIntact(t *testing.T) {
	// A tool message with no subsequent assistant message must NOT be collapsed.
	bigOutput := strings.Repeat("Z", 5000)
	history := []client.ChatMessage{
		{Role: "assistant", ToolCalls: []client.ToolCall{
			{ID: "call-x", Function: client.FunctionCall{Name: "bash", Arguments: `{}`}},
		}},
		{Role: "tool", ToolCallID: "call-x", Content: bigOutput},
		// No assistant message after — not consumed.
	}
	// Add filler to push outside recent window.
	for i := 0; i < 9; i++ {
		history = append(history, client.ChatMessage{Role: "user", Content: "filler"})
	}

	collapseConsumedToolOutputs(history)

	if history[1].Content != bigOutput {
		t.Fatalf("expected unconsumed tool content to be untouched, got len=%d", len(history[1].Content))
	}
}

func TestConsumedToolOutputStatus_Classifications(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"Command timed out after 30s", "timeout"},
		{"Command cancelled by context", "cancelled"},
		{"Error executing command: permission denied", "error"},
		{"Command failed with exit code 1\nsome output", "failed"},
		{"some requires explicit approval text", "blocked"},
		{"normal output", "ok"},
	}
	for _, c := range cases {
		got := consumedToolOutputStatus(c.content)
		if got != c.want {
			t.Errorf("consumedToolOutputStatus(%q) = %q, want %q", c.content[:min(40, len(c.content))], got, c.want)
		}
	}
}

func TestBuildConsumedSummary_ContainsRequiredFields(t *testing.T) {
	content := strings.Repeat("line of output\n", 200) // ~3000 chars
	summary := buildConsumedSummary("bash", content)

	if !strings.HasPrefix(summary, consumedPrefix) {
		t.Fatalf("expected consumed prefix")
	}
	if !strings.Contains(summary, "bash") {
		t.Fatalf("expected tool name in summary")
	}
	if !strings.Contains(summary, "ok") {
		t.Fatalf("expected status in summary")
	}
	if len(summary) > historyConsumedExcerptOK+100 { // 100 for header overhead
		t.Fatalf("success summary too long: %d chars", len(summary))
	}
}

// buildHistoryWithOlderToolResult constructs a history where the tool message
// at index 1 is outside the recent window and has a subsequent assistant message.
func buildHistoryWithOlderToolResult(toolCallID, toolName, content string, totalLen int) []client.ChatMessage {
	history := []client.ChatMessage{
		{Role: "assistant", ToolCalls: []client.ToolCall{
			{ID: toolCallID, Function: client.FunctionCall{Name: toolName, Arguments: `{}`}},
		}},
		{Role: "tool", ToolCallID: toolCallID, Content: content},
		{Role: "assistant", Content: "processed"},
	}
	// Fill to totalLen to push indices 0-2 outside recent window.
	for len(history) < totalLen {
		history = append(history, client.ChatMessage{Role: "user", Content: "filler"})
	}
	return history
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------

func TestCompactHistoryForContext_TrimsOldReasoningAndToolOutputs(t *testing.T) {
	history := make([]client.ChatMessage, 0, 10)
	for i := 0; i < 10; i++ {
		history = append(history, client.ChatMessage{
			Role:             "assistant",
			Content:          "assistant content",
			ReasoningContent: strings.Repeat("R", 1500),
		})
	}
	history[1] = client.ChatMessage{Role: "tool", Content: strings.Repeat("T", 5000)}
	history[9] = client.ChatMessage{Role: "tool", Content: strings.Repeat("Z", 5000)}

	compactHistoryForContext(history)

	if history[0].ReasoningContent != "" {
		t.Fatalf("expected old assistant reasoning to be dropped, got len=%d", len(history[0].ReasoningContent))
	}
	if len(history[1].Content) > historyToolContentMaxCharsOlder {
		t.Fatalf("expected old tool content to be compacted to <= %d chars, got %d", historyToolContentMaxCharsOlder, len(history[1].Content))
	}
	if len(history[8].ReasoningContent) > historyReasoningMaxCharsRecent {
		t.Fatalf("expected recent assistant reasoning <= %d chars, got %d", historyReasoningMaxCharsRecent, len(history[8].ReasoningContent))
	}
	if len(history[9].Content) > historyToolContentMaxCharsRecent {
		t.Fatalf("expected recent tool content <= %d chars, got %d", historyToolContentMaxCharsRecent, len(history[9].Content))
	}
}
