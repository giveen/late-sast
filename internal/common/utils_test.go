package common

import (
	"late/internal/client"
	"testing"
)

func TestReplacePlaceholders(t *testing.T) {
	tests := []struct {
		text         string
		placeholders map[string]string
		expected     string
	}{
		{
			text:         "Hello ${{CWD}}",
			placeholders: map[string]string{"${{CWD}}": "/tmp"},
			expected:     "Hello /tmp",
		},
		{
			text:         "No placeholder here",
			placeholders: map[string]string{"${{CWD}}": "/tmp"},
			expected:     "No placeholder here",
		},
		{
			text:         "Multiple ${{CWD}} in ${{CWD}}",
			placeholders: map[string]string{"${{CWD}}": "/home"},
			expected:     "Multiple /home in /home",
		},
	}

	for _, tt := range tests {
		result := ReplacePlaceholders(tt.text, tt.placeholders)
		if result != tt.expected {
			t.Errorf("ReplacePlaceholders(%q, %v) = %q; want %q", tt.text, tt.placeholders, result, tt.expected)
		}
	}
}

func TestEstimateTokenCount(t *testing.T) {
	tests := []struct {
		text     string
		expected int
	}{
		{"", 0},
		{"a", 0},              // 1/3.5 = 0.28 -> 0
		{"abcd", 1},           // 4/3.5 = 1.14 -> 1
		{"abcde", 1},          // 5/3.5 = 1.42 -> 1
		{"12345678", 2},       // 8/3.5 = 2.28 -> 2
		{"123456789", 2},      // 9/3.5 = 2.57 -> 2
		{"1234567890", 2},     // 10/3.5 = 2.85 -> 2
		{"this is a test", 4}, // 14/3.5 = 4.0 -> 4
	}

	for _, tt := range tests {
		result := EstimateTokenCount(tt.text)
		if result != tt.expected {
			t.Errorf("EstimateTokenCount(%q) = %d; want %d", tt.text, result, tt.expected)
		}
	}
}

func TestEstimateMessageTokens(t *testing.T) {
	msg := client.ChatMessage{
		Role:             "assistant",
		Content:          "Hello",
		ReasoningContent: "Thinking...",
		ToolCalls: []client.ToolCall{
			{
				Function: client.FunctionCall{
					Name:      "test_tool",
					Arguments: `{"arg1": "val1"}`,
				},
			},
		},
	}

	// "Hello" = 5 chars -> 1 token
	// "Thinking..." = 11 chars -> 3 tokens
	// "test_tool" = 9 chars -> 2 tokens
	// `{"arg1": "val1"}` = 16 chars -> 4 tokens
	// Message overhead = 4 tokens
	// Total = 1 + 3 + 2 + 4 + 4 = 14 tokens
	expected := 14
	result := EstimateMessageTokens(msg)
	if result != expected {
		t.Errorf("EstimateMessageTokens() = %d; want %d", result, expected)
	}
}

func TestEstimateEventTokens(t *testing.T) {
	event := ContentEvent{
		Content:          "Part1",
		ReasoningContent: "Reason",
	}

	// "Part1" = 5 chars -> 1 token
	// "Reason" = 6 chars -> 1 token
	// Total = 1 + 1 = 2 tokens
	expected := 2
	result := EstimateEventTokens(event)
	if result != expected {
		t.Errorf("EstimateEventTokens() = %d; want %d", result, expected)
	}
}

func TestCalculateHistoryTokens(t *testing.T) {
	tests := []struct {
		name         string
		history      []client.ChatMessage
		systemPrompt string
		tools        []client.ToolDefinition
		expected     int
	}{
		{
			name:         "empty history with system prompt",
			history:      []client.ChatMessage{},
			systemPrompt: "You are an assistant",
			tools:        nil,
			expected:     15, // "You are an assistant" = 20 chars -> 5 tokens + 10 overhead = 15
		},
		{
			name: "single user message",
			history: []client.ChatMessage{
				{
					Role:    "user",
					Content: "Hello",
				},
			},
			systemPrompt: "",
			tools:        nil,
			expected:     15, // System overhead (10) + msg content (1) + msg overhead (4) = 15
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateHistoryTokens(tt.history, tt.systemPrompt, tt.tools)
			if result != tt.expected {
				t.Errorf("CalculateHistoryTokens() = %d; want %d", result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EstimateToolDefinitionTokens unit tests
// ---------------------------------------------------------------------------

func TestEstimateToolDefinitionTokens_Nil(t *testing.T) {
	if got := EstimateToolDefinitionTokens(nil); got != 0 {
		t.Errorf("EstimateToolDefinitionTokens(nil) = %d, want 0", got)
	}
}

func TestEstimateToolDefinitionTokens_Empty(t *testing.T) {
	if got := EstimateToolDefinitionTokens([]client.ToolDefinition{}); got != 0 {
		t.Errorf("EstimateToolDefinitionTokens([]) = %d, want 0", got)
	}
}

func TestEstimateToolDefinitionTokens_SingleTool(t *testing.T) {
	tools := []client.ToolDefinition{{
		Type: "function",
		Function: client.FunctionDefinition{
			Name:        "read_file",
			Description: "Read a file from disk and return its contents",
			Parameters:  []byte(`{"type":"object","properties":{"path":{"type":"string"}}}`),
		},
	}}
	got := EstimateToolDefinitionTokens(tools)
	if got <= 0 {
		t.Errorf("EstimateToolDefinitionTokens(single tool) = %d, want > 0", got)
	}
}

func TestEstimateToolDefinitionTokens_MoreToolsMoreTokens(t *testing.T) {
	makeTool := func(name, desc string) client.ToolDefinition {
		return client.ToolDefinition{
			Type: "function",
			Function: client.FunctionDefinition{
				Name:        name,
				Description: desc,
				Parameters:  []byte(`{}`),
			},
		}
	}
	one := EstimateToolDefinitionTokens([]client.ToolDefinition{makeTool("tool_a", "description of tool a")})
	two := EstimateToolDefinitionTokens([]client.ToolDefinition{
		makeTool("tool_a", "description of tool a"),
		makeTool("tool_b", "description of tool b"),
	})
	if two <= one {
		t.Errorf("two tools (%d tokens) should have more tokens than one (%d)", two, one)
	}
}
