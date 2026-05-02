package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSanitizeMessagesForRequest_DropsInvalidToolCalls(t *testing.T) {
	messages := []ChatMessage{
		{
			Role: "assistant",
			ToolCalls: []ToolCall{
				{
					ID:   "valid-1",
					Type: "function",
					Function: FunctionCall{
						Name:      "bash",
						Arguments: "{\"command\":\"echo ok\"}",
					},
				},
				{
					ID:   "invalid-1",
					Type: "function",
					Function: FunctionCall{
						Name:      "bash",
						Arguments: "{\"command\":",
					},
				},
			},
		},
	}

	sanitized := sanitizeMessagesForRequest(messages)
	if len(sanitized) != 1 {
		t.Fatalf("expected 1 message, got %d", len(sanitized))
	}
	if len(sanitized[0].ToolCalls) != 1 {
		t.Fatalf("expected 1 valid tool call, got %d", len(sanitized[0].ToolCalls))
	}
	if sanitized[0].ToolCalls[0].ID != "valid-1" {
		t.Fatalf("expected valid tool call to remain, got %q", sanitized[0].ToolCalls[0].ID)
	}
}

func TestSanitizeMessagesForRequest_LeavesNonToolMessagesUntouched(t *testing.T) {
	messages := []ChatMessage{
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: "hello"},
	}

	sanitized := sanitizeMessagesForRequest(messages)
	if len(sanitized) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(sanitized))
	}
	if sanitized[0].Content != "hi" || sanitized[1].Content != "hello" {
		t.Fatalf("expected content to remain unchanged")
	}
}

func TestShouldRetryWithoutTools_ExactParse500(t *testing.T) {
	req := ChatCompletionRequest{
		Tools: []ToolDefinition{{Type: "function", Function: FunctionDefinition{Name: "bash"}}},
	}
	err := errString("API error (500): Failed to parse tool call arguments as JSON: [ json.exception.parse_error.101 ]")
	if !shouldRetryWithoutTools(err, req) {
		t.Fatalf("expected retryable parse-500 error")
	}
}

func TestShouldRetryWithoutTools_NonParse500(t *testing.T) {
	req := ChatCompletionRequest{
		Tools: []ToolDefinition{{Type: "function", Function: FunctionDefinition{Name: "bash"}}},
	}
	err := errString("API error (500): internal server error")
	if shouldRetryWithoutTools(err, req) {
		t.Fatalf("did not expect retry for non-parse 500")
	}
}

func TestDisableToolsForRetry_StripsToolsAndToolCalls(t *testing.T) {
	req := ChatCompletionRequest{
		Tools:      []ToolDefinition{{Type: "function", Function: FunctionDefinition{Name: "bash"}}},
		ToolChoice: "auto",
		Messages: []ChatMessage{{
			Role: "assistant",
			ToolCalls: []ToolCall{{
				ID:       "tc1",
				Function: FunctionCall{Name: "bash", Arguments: "{\"command\":\"echo ok\"}"},
			}},
		}},
	}

	out := disableToolsForRetry(req)
	if len(out.Tools) != 0 {
		t.Fatalf("expected tools removed")
	}
	if out.ToolChoice != nil {
		t.Fatalf("expected tool_choice cleared")
	}
	if len(out.Messages) != 1 || len(out.Messages[0].ToolCalls) != 0 {
		t.Fatalf("expected message tool_calls stripped")
	}
}

func TestChatCompletionStream_RetriesOnceOnParse500(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/props" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var req ChatCompletionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		attempt := attempts.Add(1)
		switch attempt {
		case 1:
			if len(req.Tools) == 0 {
				t.Fatalf("expected first request to include tools")
			}
			if len(req.Messages) == 0 || len(req.Messages[0].ToolCalls) == 0 {
				t.Fatalf("expected first request to include assistant tool calls")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":{"message":"Failed to parse tool call arguments as JSON: [ json.exception.parse_error.101 ]"}}`)
		case 2:
			if len(req.Tools) != 0 {
				t.Fatalf("expected retry request to disable tools, got %d tools", len(req.Tools))
			}
			for _, msg := range req.Messages {
				if len(msg.ToolCalls) != 0 {
					t.Fatalf("expected retry request to strip historical tool calls")
				}
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"choices\":[{\"index\":0,\"delta\":{\"content\":\"retry ok\"},\"finish_reason\":\"stop\"}]}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
		default:
			t.Fatalf("expected at most 2 attempts, got %d", attempt)
		}
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL, Model: "test-model", Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream, errCh := client.ChatCompletionStream(ctx, ChatCompletionRequest{
		Messages: []ChatMessage{{
			Role: "assistant",
			ToolCalls: []ToolCall{{
				ID:   "tc1",
				Type: "function",
				Function: FunctionCall{
					Name:      "bash",
					Arguments: `{"command":"echo hi"}`,
				},
			}},
		}},
		Tools: []ToolDefinition{{Type: "function", Function: FunctionDefinition{Name: "bash"}}},
	})

	var content strings.Builder
	for chunk := range stream {
		if len(chunk.Choices) > 0 {
			content.WriteString(chunk.Choices[0].Delta.Content)
		}
	}

	for err := range errCh {
		if err != nil {
			t.Fatalf("unexpected stream error: %v", err)
		}
	}

	if got := content.String(); got != "retry ok" {
		t.Fatalf("expected streamed content %q, got %q", "retry ok", got)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected exactly 2 attempts, got %d", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
