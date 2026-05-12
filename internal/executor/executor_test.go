package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"late/internal/client"
	"late/internal/common"
	"late/internal/pathutil"
	"late/internal/session"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStreamAccumulator_Append(t *testing.T) {
	acc := StreamAccumulator{}

	// Append content
	acc.Append(common.StreamResult{Content: "Hello "})
	acc.Append(common.StreamResult{Content: "world"})

	if acc.Content != "Hello world" {
		t.Errorf("expected 'Hello world', got '%s'", acc.Content)
	}
}

func TestStreamAccumulator_AppendReasoning(t *testing.T) {
	acc := StreamAccumulator{}

	acc.Append(common.StreamResult{ReasoningContent: "Step 1. "})
	acc.Append(common.StreamResult{ReasoningContent: "Step 2."})

	if acc.Reasoning != "Step 1. Step 2." {
		t.Errorf("expected 'Step 1. Step 2.', got '%s'", acc.Reasoning)
	}
}

func TestStreamAccumulator_AppendToolCalls(t *testing.T) {
	acc := StreamAccumulator{}

	// First delta creates a new tool call
	acc.Append(common.StreamResult{
		ToolCalls: []client.ToolCall{
			{Index: 0, ID: "call_1", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path"`}},
		},
	})

	// Second delta appends to existing tool call arguments
	acc.Append(common.StreamResult{
		ToolCalls: []client.ToolCall{
			{Index: 0, Function: client.FunctionCall{Arguments: `: "test.go"}`}},
		},
	})

	if len(acc.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(acc.ToolCalls))
	}
	if acc.ToolCalls[0].Function.Name != "read_file" {
		t.Errorf("expected tool name 'read_file', got '%s'", acc.ToolCalls[0].Function.Name)
	}
	expected := `{"path": "test.go"}`
	if acc.ToolCalls[0].Function.Arguments != expected {
		t.Errorf("expected args '%s', got '%s'", expected, acc.ToolCalls[0].Function.Arguments)
	}
	if acc.ToolCalls[0].ID != "call_1" {
		t.Errorf("expected ID 'call_1', got '%s'", acc.ToolCalls[0].ID)
	}
}

func TestStreamAccumulator_AppendMultipleToolCalls(t *testing.T) {
	acc := StreamAccumulator{}

	acc.Append(common.StreamResult{
		ToolCalls: []client.ToolCall{
			{Index: 0, ID: "call_1", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path": "a.go"}`}},
		},
	})
	acc.Append(common.StreamResult{
		ToolCalls: []client.ToolCall{
			{Index: 1, ID: "call_2", Function: client.FunctionCall{Name: "write_file", Arguments: `{"path": "."}`}},
		},
	})

	if len(acc.ToolCalls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(acc.ToolCalls))
	}
	if acc.ToolCalls[1].Function.Name != "write_file" {
		t.Errorf("expected 'write_file', got '%s'", acc.ToolCalls[1].Function.Name)
	}
}

func TestStreamAccumulator_Reset(t *testing.T) {
	acc := StreamAccumulator{
		Content:   "test",
		Reasoning: "thought",
		ToolCalls: []client.ToolCall{{ID: "1"}},
	}

	acc.Reset()

	if acc.Content != "" || acc.Reasoning != "" || acc.ToolCalls != nil {
		t.Error("expected all fields to be zero after Reset")
	}
}

func TestStreamAccumulator_NameUpdate(t *testing.T) {
	acc := StreamAccumulator{}

	// First delta: tool call with empty name (streaming)
	acc.Append(common.StreamResult{
		ToolCalls: []client.ToolCall{
			{Index: 0, ID: "call_1", Function: client.FunctionCall{Name: "", Arguments: `{`}},
		},
	})

	// Second delta: name arrives
	acc.Append(common.StreamResult{
		ToolCalls: []client.ToolCall{
			{Index: 0, Function: client.FunctionCall{Name: "bash", Arguments: `"cmd": "ls"}`}},
		},
	})

	if acc.ToolCalls[0].Function.Name != "bash" {
		t.Errorf("expected name to be updated to 'bash', got '%s'", acc.ToolCalls[0].Function.Name)
	}
}

// TestExecuteToolCalls_NotFound verifies that missing tools produce an error message
func TestExecuteToolCalls_NotFound(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", false)

	toolCalls := []client.ToolCall{
		{ID: "tc_1", Function: client.FunctionCall{Name: "nonexistent", Arguments: "{}"}},
	}

	err := ExecuteToolCalls(context.Background(), sess, toolCalls, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have added a tool result message with error
	if len(sess.History) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(sess.History))
	}
	if sess.History[0].Role != "tool" {
		t.Errorf("expected role 'tool', got '%s'", sess.History[0].Role)
	}
}

// TestExecuteToolCalls_Denied verifies denied confirmation produces cancel message
func TestExecuteToolCalls_Denied(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", true)

	// Register bash tool which requires confirmation
	RegisterTools(sess.Registry, nil)

	toolCalls := []client.ToolCall{
		{ID: "tc_1", Function: client.FunctionCall{Name: "bash", Arguments: `{"command":"echo hi"}`}},
	}

	denyMiddleware := func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			return "Tool execution cancelled by user", nil
		}
	}

	err := ExecuteToolCalls(context.Background(), sess, toolCalls, []common.ToolMiddleware{denyMiddleware})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sess.History) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(sess.History))
	}
	if sess.History[0].Content != "Tool execution cancelled by user" {
		t.Errorf("expected cancel message, got '%s'", sess.History[0].Content)
	}
}

// TestExecuteToolCalls_NoMiddlewareFailsClosed verifies shell commands cannot
// run when confirmation middleware is missing.
func TestExecuteToolCalls_NoMiddlewareFailsClosed(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", true)

	RegisterTools(sess.Registry, map[string]bool{"bash": true})

	toolCalls := []client.ToolCall{
		{ID: "tc_1", Function: client.FunctionCall{Name: "bash", Arguments: `{"command":"echo hi"}`}},
	}

	err := ExecuteToolCalls(context.Background(), sess, toolCalls, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sess.History) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(sess.History))
	}

	if !strings.Contains(sess.History[0].Content, "requires explicit approval") {
		t.Fatalf("expected fail-closed approval message, got %q", sess.History[0].Content)
	}
}

func TestExecuteToolCallsWithStats_NoMiddlewareCountsBlocked(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", true)

	RegisterTools(sess.Registry, map[string]bool{"bash": true})
	toolCalls := []client.ToolCall{{ID: "tc_1", Function: client.FunctionCall{Name: "bash", Arguments: `{"command":"echo hi"}`}}}

	stats, err := ExecuteToolCallsWithStats(context.Background(), sess, toolCalls, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Total != 1 || stats.Blocked != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestToolCallSignature_Stable(t *testing.T) {
	calls := []client.ToolCall{
		{Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"a.go"}`}},
		{Function: client.FunctionCall{Name: "bash", Arguments: `{"command":"ls"}`}},
	}
	left := toolCallSignature(calls)
	right := toolCallSignature(calls)
	if left == "" || left != right {
		t.Fatalf("expected stable non-empty signature, got left=%q right=%q", left, right)
	}
}

func TestConsecutiveDuplicateToolTurns(t *testing.T) {
	a := "sig-a"
	b := "sig-b"

	tests := []struct {
		name    string
		history []string
		current string
		want    int
	}{
		{name: "empty current", history: []string{a, a}, current: "", want: 0},
		{name: "no match", history: []string{a, b}, current: a, want: 0},
		{name: "one trailing match", history: []string{a, b}, current: b, want: 1},
		{name: "two trailing matches", history: []string{a, a}, current: a, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := consecutiveDuplicateToolTurns(tt.history, tt.current)
			if got != tt.want {
				t.Fatalf("consecutiveDuplicateToolTurns(%v, %q) = %d, want %d", tt.history, tt.current, got, tt.want)
			}
		})
	}
}

func TestRepeatedToolPlanCycle(t *testing.T) {
	a := "sig-a"
	b := "sig-b"
	c := "sig-c"

	tests := []struct {
		name        string
		history     []string
		current     string
		maxCycleLen int
		wantLen     int
		wantTurns   int
	}{
		{name: "detects abab", history: []string{a, b, a}, current: b, maxCycleLen: 2, wantLen: 2, wantTurns: 4},
		{name: "does not flag consecutive duplicates as cycle", history: []string{a, a, a}, current: a, maxCycleLen: 2, wantLen: 0, wantTurns: 0},
		{name: "does not flag incomplete pattern", history: []string{a, b}, current: a, maxCycleLen: 2, wantLen: 0, wantTurns: 0},
		{name: "does not flag mismatched tail", history: []string{a, b, c}, current: b, maxCycleLen: 2, wantLen: 0, wantTurns: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLen, gotTurns := repeatedToolPlanCycle(tt.history, tt.current, tt.maxCycleLen)
			if gotLen != tt.wantLen || gotTurns != tt.wantTurns {
				t.Fatalf("repeatedToolPlanCycle(%v, %q, %d) = (%d, %d), want (%d, %d)", tt.history, tt.current, tt.maxCycleLen, gotLen, gotTurns, tt.wantLen, tt.wantTurns)
			}
		})
	}
}

// TestConsumeStream verifies ConsumeStream drains a channel correctly
func TestConsumeStream(t *testing.T) {
	outCh := make(chan common.StreamResult, 3)
	errCh := make(chan error, 1)

	outCh <- common.StreamResult{Content: "Hello "}
	outCh <- common.StreamResult{Content: "world"}
	outCh <- common.StreamResult{ReasoningContent: "thinking..."}
	close(outCh)
	close(errCh)

	var chunks int
	acc, err := ConsumeStream(context.Background(), outCh, errCh, func(r common.StreamResult) {
		chunks++
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acc.Content != "Hello world" {
		t.Errorf("expected 'Hello world', got '%s'", acc.Content)
	}
	if acc.Reasoning != "thinking..." {
		t.Errorf("expected 'thinking...', got '%s'", acc.Reasoning)
	}
	if chunks != 3 {
		t.Errorf("expected 3 chunks, got %d", chunks)
	}
}

// TestConsumeStream_WithError verifies stream errors are returned
func TestConsumeStream_WithError(t *testing.T) {
	outCh := make(chan common.StreamResult, 1)
	errCh := make(chan error, 1)

	outCh <- common.StreamResult{Content: "partial"}
	close(outCh)
	errCh <- context.DeadlineExceeded
	close(errCh)

	acc, err := ConsumeStream(context.Background(), outCh, errCh, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if acc.Content != "partial" {
		t.Errorf("expected 'partial', got '%s'", acc.Content)
	}
}

// TestRegisterTools verifies that tools are registered
func TestRegisterTools(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", false)

	enabledTools := map[string]bool{
		"read_file":   true,
		"write_file":  true,
		"target_edit": true,
		"bash":        false,
	}
	RegisterTools(sess.Registry, enabledTools)

	expected := []string{"read_file", "write_file", "target_edit"}
	for _, name := range expected {
		if sess.Registry.Get(name) == nil {
			t.Errorf("expected tool '%s' to be registered", name)
		}
	}

	// Bash should NOT be registered when enableBash is false
	if sess.Registry.Get("bash") != nil {
		t.Error("bash should not be registered when enableBash is false")
	}
}

// TestRegisterTools_WithBash verifies bash tool is registered when enabled
func TestRegisterTools_WithBash(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", false)

	enabledTools := map[string]bool{
		"bash": true,
	}
	RegisterTools(sess.Registry, enabledTools)

	if sess.Registry.Get("bash") == nil {
		t.Error("bash should be registered when enableBash is true")
	}
}

func TestRegisterTools_WithReadFile(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", false)

	enabledTools := map[string]bool{
		"read_file": true,
	}
	RegisterTools(sess.Registry, enabledTools)

	// Verify ReadFileTool is still there (implied by default check), but maybe check its description/params if needed?
	// For now, just ensuring no error is thrown during registration is good enough.
	if sess.Registry.Get("read_file") == nil {
		t.Error("read_file should be registered")
	}
}

func TestBuildSkillDirs_AdditiveOrdering(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	configured := filepath.Join(t.TempDir(), "custom-skills")
	userSkillsDir, err := pathutil.LateSkillsDir()
	if err != nil {
		t.Fatalf("LateSkillsDir() error = %v", err)
	}

	got := buildSkillDirs(configured)
	if len(got) != 3 {
		t.Fatalf("expected 3 skill dirs, got %d: %v", len(got), got)
	}
	if got[0] != configured {
		t.Fatalf("expected configured dir first, got %q", got[0])
	}
	if got[1] != userSkillsDir {
		t.Fatalf("expected user skills dir second, got %q (want %q)", got[1], userSkillsDir)
	}
	if got[2] != pathutil.LateProjectSkillsDir() {
		t.Fatalf("expected project skills dir third, got %q", got[2])
	}
}

func TestBuildSkillDirs_DeduplicatesConfiguredAndDefault(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	userSkillsDir, err := pathutil.LateSkillsDir()
	if err != nil {
		t.Fatalf("LateSkillsDir() error = %v", err)
	}

	got := buildSkillDirs(userSkillsDir)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique skill dirs, got %d: %v", len(got), got)
	}
	if got[0] != userSkillsDir {
		t.Fatalf("expected user/configured dir first, got %q", got[0])
	}
	if got[1] != pathutil.LateProjectSkillsDir() {
		t.Fatalf("expected project skills dir second, got %q", got[1])
	}
}

// TestExecuteParallelBatch verifies that all parallel-safe tool calls in a
// batch are executed concurrently and results are returned in original order.
func TestExecuteParallelBatch(t *testing.T) {
	const numTools = 4
	order := make(chan int, numTools)

	runner := func(_ context.Context, tc client.ToolCall) (string, error) {
		order <- len(order) // record execution
		return "result:" + tc.ID, nil
	}

	toolCalls := make([]client.ToolCall, numTools)
	for i := range toolCalls {
		toolCalls[i] = client.ToolCall{
			ID:       fmt.Sprintf("tc_%d", i),
			Function: client.FunctionCall{Name: "read_file", Arguments: fmt.Sprintf(`{"path":"file_%d.go"}`, i)},
		}
	}

	results := executeParallelBatch(context.Background(), context.Background(), toolCalls, runner, nil, nil)

	if len(results) != numTools {
		t.Fatalf("expected %d results, got %d", numTools, len(results))
	}
	for i, r := range results {
		want := fmt.Sprintf("result:tc_%d", i)
		if r.result != want {
			t.Errorf("[%d] got %q, want %q", i, r.result, want)
		}
		if r.runErr != nil {
			t.Errorf("[%d] unexpected error: %v", i, r.runErr)
		}
	}
}

func TestExecuteParallelBatch_DeduplicatesIdenticalCalls(t *testing.T) {
	var runs int32
	runner := func(_ context.Context, tc client.ToolCall) (string, error) {
		atomic.AddInt32(&runs, 1)
		return "result:" + tc.Function.Arguments, nil
	}

	toolCalls := []client.ToolCall{
		{ID: "tc_1", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"a.go"}`}},
		{ID: "tc_2", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"a.go"}`}},
		{ID: "tc_3", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"b.go"}`}},
	}

	results := executeParallelBatch(context.Background(), context.Background(), toolCalls, runner, nil, nil)
	if got, want := atomic.LoadInt32(&runs), int32(2); got != want {
		t.Fatalf("runner called %d times, want %d", got, want)
	}
	if len(results) != len(toolCalls) {
		t.Fatalf("expected %d results, got %d", len(toolCalls), len(results))
	}
	if results[1].result != results[0].result {
		t.Fatalf("expected duplicate call result to match leader, got %q vs %q", results[1].result, results[0].result)
	}
	if !results[1].fromDedup {
		t.Fatal("expected duplicate call to be marked fromDedup")
	}
	if results[0].fromDedup {
		t.Fatal("expected first call not to be marked fromDedup")
	}
}

func TestExecuteParallelBatch_DedupPropagatesRunError(t *testing.T) {
	var runs int32
	runErr := errors.New("boom")
	runner := func(_ context.Context, tc client.ToolCall) (string, error) {
		atomic.AddInt32(&runs, 1)
		if tc.Function.Arguments == `{"path":"a.go"}` {
			return "", runErr
		}
		return "ok", nil
	}

	toolCalls := []client.ToolCall{
		{ID: "tc_1", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"a.go"}`}},
		{ID: "tc_2", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"a.go"}`}},
	}

	results := executeParallelBatch(context.Background(), context.Background(), toolCalls, runner, nil, nil)
	if got, want := atomic.LoadInt32(&runs), int32(1); got != want {
		t.Fatalf("runner called %d times, want %d", got, want)
	}
	if results[0].runErr == nil {
		t.Fatal("expected leader runErr")
	}
	if results[1].runErr == nil || results[1].runErr.Error() != runErr.Error() {
		t.Fatalf("expected duplicate runErr %q, got %#v", runErr.Error(), results[1].runErr)
	}
	if !results[1].fromDedup {
		t.Fatal("expected duplicate entry marked fromDedup")
	}
}

// TestExecuteToolCallsWithStats_ParallelBatch verifies that a batch of all
// parallel-safe tool calls is executed and all results land in session history.
func TestExecuteToolCallsWithStats_ParallelBatch(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:0"})
	histPath := filepath.Join(t.TempDir(), "history.json")
	sess := session.New(c, histPath, nil, "", false)

	// Register a stub read_file tool that returns the call ID.
	stub := &stubTool{name: "read_file"}
	sess.Registry.Register(stub)

	toolCalls := []client.ToolCall{
		{ID: "tc_1", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"a.go"}`}},
		{ID: "tc_2", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"b.go"}`}},
		{ID: "tc_3", Function: client.FunctionCall{Name: "read_file", Arguments: `{"path":"c.go"}`}},
	}

	passMiddleware := func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			return next(ctx, tc)
		}
	}

	stats, err := ExecuteToolCallsWithStats(context.Background(), sess, toolCalls, []common.ToolMiddleware{passMiddleware}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Total != 3 {
		t.Errorf("expected Total=3, got %d", stats.Total)
	}
	// All three tool calls must appear in history.
	if len(sess.History) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(sess.History))
	}
	seen := map[string]bool{}
	for _, msg := range sess.History {
		seen[msg.ToolCallID] = true
	}
	for _, tc := range toolCalls {
		if !seen[tc.ID] {
			t.Errorf("missing history entry for tool call %q", tc.ID)
		}
	}
}

// stubTool is a minimal common.Tool that returns an empty string result.
type stubTool struct{ name string }

func (s *stubTool) Name() string                { return s.name }
func (s *stubTool) Description() string         { return "" }
func (s *stubTool) Parameters() json.RawMessage { return nil }
func (s *stubTool) Execute(_ context.Context, _ json.RawMessage) (string, error) {
	return "", nil
}
func (s *stubTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (s *stubTool) CallString(_ json.RawMessage) string         { return "" }
