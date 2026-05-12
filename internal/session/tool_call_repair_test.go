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

func TestRepairToolCallArguments_StripFences(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"plain fence", "```json\n{\"query\": \"foo\"}\n```"},
		{"unlabeled fence", "```\n{\"query\": \"foo\"}\n```"},
		{"fence with trailing newline", "```json\n{\"q\": 1}\n```\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := repairToolCallArguments(tc.input)
			if !ok {
				t.Fatalf("expected repair to succeed, got false for input %q", tc.input)
			}
			if !json.Valid([]byte(got)) {
				t.Fatalf("expected valid JSON after repair, got %q", got)
			}
		})
	}
}

func TestRepairToolCallArguments_ExtractFromProse(t *testing.T) {
	input := `Here is the JSON: {"pattern": "foo", "limit": 10} — use it carefully`
	got, ok := repairToolCallArguments(input)
	if !ok {
		t.Fatalf("expected extract-from-prose repair to succeed")
	}
	if !json.Valid([]byte(got)) {
		t.Fatalf("expected valid JSON, got %q", got)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if m["pattern"] != "foo" {
		t.Fatalf("unexpected payload: %#v", m)
	}
}

func TestRepairToolCallArguments_PythonLiterals(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantKey string
		wantVal interface{}
	}{
		{"True", `{"enabled": True}`, "enabled", true},
		{"False", `{"enabled": False}`, "enabled", false},
		{"None", `{"value": None}`, "value", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := repairToolCallArguments(tc.input)
			if !ok {
				t.Fatalf("expected repair to succeed for %q", tc.input)
			}
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(got), &m); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if m[tc.wantKey] != tc.wantVal {
				t.Fatalf("expected %q=%v, got %v", tc.wantKey, tc.wantVal, m[tc.wantKey])
			}
		})
	}
}

func TestRepairToolCallArguments_NonJSONNumericTokens(t *testing.T) {
	cases := []string{
		`{"score": NaN}`,
		`{"score": Infinity}`,
		`{"score": -Infinity}`,
	}
	for _, input := range cases {
		got, ok := repairToolCallArguments(input)
		if !ok {
			t.Fatalf("expected repair to succeed for %q", input)
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(got), &m); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if m["score"] != nil {
			t.Fatalf("expected score=null, got %v", m["score"])
		}
	}
}

func TestRepairToolCallArguments_EllipsisInArray(t *testing.T) {
	input := `{"items": [1, 2, ...]}`
	got, ok := repairToolCallArguments(input)
	if !ok {
		t.Fatalf("expected repair to succeed")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
}

func TestRepairToolCallArguments_LineComments(t *testing.T) {
	input := `{"pattern": "foo", // search pattern
"limit": 10}`
	got, ok := repairToolCallArguments(input)
	if !ok {
		t.Fatalf("expected repair to succeed")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if m["pattern"] != "foo" {
		t.Fatalf("unexpected payload: %#v", m)
	}
}

func TestRepairToolCallArguments_BlockComments(t *testing.T) {
	input := `{"pattern": "foo" /* the pattern */, "limit": 10}`
	got, ok := repairToolCallArguments(input)
	if !ok {
		t.Fatalf("expected repair to succeed")
	}
	if !json.Valid([]byte(got)) {
		t.Fatalf("expected valid JSON, got %q", got)
	}
}

func TestRepairToolCallArguments_PreservesStringContent(t *testing.T) {
	// Ensure None/True/False/NaN inside string VALUES are not corrupted.
	input := `{"message": "Value is None or True", "score": NaN}`
	got, ok := repairToolCallArguments(input)
	if !ok {
		t.Fatalf("expected repair to succeed")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if m["message"] != "Value is None or True" {
		t.Fatalf("string value was corrupted: %q", m["message"])
	}
	if m["score"] != nil {
		t.Fatalf("expected score=null, got %v", m["score"])
	}
}

func TestAddAssistantMessageWithTools_DropsEmptyNameCall(t *testing.T) {
	s := New(client.NewClient(client.Config{}), "", nil, "", true)

	calls := []client.ToolCall{
		{
			ID:   "call-empty-name",
			Type: "function",
			Function: client.FunctionCall{
				Name:      "",
				Arguments: `{"query": "foo"}`,
			},
		},
	}

	valid, err := s.AddAssistantMessageWithTools("", "", calls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 0 {
		t.Fatalf("expected empty-name call to be dropped, got %d", len(valid))
	}
}

func TestAddAssistantMessageWithTools_DropsEmptyArgsCall(t *testing.T) {
	s := New(client.NewClient(client.Config{}), "", nil, "", true)

	calls := []client.ToolCall{
		{
			ID:   "call-empty-args",
			Type: "function",
			Function: client.FunctionCall{
				Name:      "search_code",
				Arguments: "",
			},
		},
	}

	valid, err := s.AddAssistantMessageWithTools("", "", calls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 0 {
		t.Fatalf("expected empty-args call to be dropped, got %d", len(valid))
	}
}

func TestToolRequiresArgs_CurrentToolNames(t *testing.T) {
	s := New(client.NewClient(client.Config{}), "", nil, "", true)
	// Unknown tools (not in the registry) are conservatively treated as requiring args.
	if !s.toolRequiresArgs("docs_resolve") {
		t.Fatal("expected unknown tool docs_resolve to conservatively require arguments")
	}
	if !s.toolRequiresArgs("ctx_index") {
		t.Fatal("expected unknown tool ctx_index to conservatively require arguments")
	}
}
