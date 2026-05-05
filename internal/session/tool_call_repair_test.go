package session

import (
	"encoding/json"
	"testing"

	"late/internal/client"
)

func TestAddAssistantMessageWithTools_RepairsTruncatedJSONArgs(t *testing.T) {
	s := New(client.NewClient(client.Config{}), "", nil, "", true)

	calls := []client.ToolCall{
		{
			ID:   "call-1",
			Type: "function",
			Function: client.FunctionCall{
				Name:      "search_code",
				Arguments: `{"pattern":"setPasswordAction|setPassword"`,
			},
		},
	}

	valid, err := s.AddAssistantMessageWithTools("", "", calls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 1 {
		t.Fatalf("expected repaired call to be kept, got %d", len(valid))
	}
	if !json.Valid([]byte(valid[0].Function.Arguments)) {
		t.Fatalf("expected repaired args to be valid JSON, got: %q", valid[0].Function.Arguments)
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(valid[0].Function.Arguments), &payload); err != nil {
		t.Fatalf("unexpected unmarshal error after repair: %v", err)
	}
	if payload["pattern"] != "setPasswordAction|setPassword" {
		t.Fatalf("unexpected repaired payload: %#v", payload)
	}
}

func TestAddAssistantMessageWithTools_SkipsUnrepairableJSONArgs(t *testing.T) {
	s := New(client.NewClient(client.Config{}), "", nil, "", true)

	calls := []client.ToolCall{
		{
			ID:   "call-2",
			Type: "function",
			Function: client.FunctionCall{
				Name:      "search_code",
				Arguments: `{"pattern":}`,
			},
		},
	}

	valid, err := s.AddAssistantMessageWithTools("", "", calls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 0 {
		t.Fatalf("expected malformed call to be skipped, got %d", len(valid))
	}
}

func TestToolRequiresArgs_CurrentToolNames(t *testing.T) {
	if !toolRequiresArgs("docs_resolve") {
		t.Fatal("expected docs_resolve to require arguments")
	}
	if !toolRequiresArgs("ctx_index") {
		t.Fatal("expected ctx_index to require arguments")
	}
}
