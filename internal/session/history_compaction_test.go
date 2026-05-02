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
