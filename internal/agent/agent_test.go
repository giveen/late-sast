package agent

import (
	"context"
	"os"
	"strings"
	"testing"

	"late/internal/client"
	"late/internal/common"
	"late/internal/orchestrator"
	"late/internal/session"
)

// TestNewSubagentOrchestratorWithGemmaThinking verifies that the gemmaThinking
// parameter correctly prepends the <|think|> token to the system prompt
func TestNewSubagentOrchestratorWithGemmaThinking(t *testing.T) {
	// Create a mock client
	cfg := client.Config{BaseURL: "http://localhost:8080"}
	c := client.NewClient(cfg)

	// Create a mock parent session
	mockHistoryPath := "/tmp/mock-session.json"
	mockHistory := []client.ChatMessage{}
	mockSession := session.New(c, mockHistoryPath, mockHistory, "mock system prompt", true)
	parent := orchestrator.NewBaseOrchestrator("parent", mockSession, nil, 100)

	// Test with gemmaThinking = true
	enabledTools := map[string]bool{"bash": true}
	child, err := NewSubagentOrchestrator(
		c,
		"test goal",
		[]string{},
		"coder",
		enabledTools,
		false, // injectCWD
		true,  // gemmaThinking
		100,   // maxTurns
		parent,
		nil, // messenger
		nil, // debugLogger
	)

	if err != nil {
		t.Fatalf("Failed to create subagent orchestrator: %v", err)
	}

	// Get the session from the child orchestrator
	childBase, ok := child.(*orchestrator.BaseOrchestrator)
	if !ok {
		t.Fatalf("Expected BaseOrchestrator, got %T", child)
	}

	sess := childBase.Session()

	// Check that the system prompt has the <|think|> prefix
	systemPrompt := sess.SystemPrompt()
	if !strings.HasPrefix(systemPrompt, "<|think|>") {
		t.Errorf("Expected system prompt to start with '<|think|>', got: %s", systemPrompt[:min(50, len(systemPrompt))]+"...")
	}

	// Test with gemmaThinking = false
	child2, err := NewSubagentOrchestrator(
		c,
		"test goal",
		[]string{},
		"coder",
		enabledTools,
		false, // injectCWD
		false, // gemmaThinking
		100,   // maxTurns
		parent,
		nil, // messenger
		nil, // debugLogger
	)

	if err != nil {
		t.Fatalf("Failed to create subagent orchestrator: %v", err)
	}

	childBase2, ok := child2.(*orchestrator.BaseOrchestrator)
	if !ok {
		t.Fatalf("Expected BaseOrchestrator, got %T", child2)
	}

	sess2 := childBase2.Session()

	// Check that the system prompt does NOT have the <|think|> prefix
	systemPrompt2 := sess2.SystemPrompt()
	if strings.HasPrefix(systemPrompt2, "<|think|>") {
		t.Errorf("Expected system prompt NOT to start with '<|think|>', got: %s", systemPrompt2[:min(50, len(systemPrompt2))]+"...")
	}
}

// TestNewSubagentOrchestratorGemmaThinkingWithCWD verifies that gemmaThinking
// works correctly together with injectCWD
func TestNewSubagentOrchestratorGemmaThinkingWithCWD(t *testing.T) {
	cfg := client.Config{BaseURL: "http://localhost:8080"}
	c := client.NewClient(cfg)

	// Create a mock parent session
	mockHistoryPath := "/tmp/mock-session.json"
	mockHistory := []client.ChatMessage{}
	mockSession := session.New(c, mockHistoryPath, mockHistory, "mock system prompt", true)
	parent := orchestrator.NewBaseOrchestrator("parent", mockSession, nil, 100)

	enabledTools := map[string]bool{"bash": true}
	child, err := NewSubagentOrchestrator(
		c,
		"test goal",
		[]string{},
		"coder",
		enabledTools,
		true, // injectCWD
		true, // gemmaThinking
		100,  // maxTurns
		parent,
		nil, // messenger
		nil, // debugLogger
	)

	if err != nil {
		t.Fatalf("Failed to create subagent orchestrator: %v", err)
	}

	childBase, ok := child.(*orchestrator.BaseOrchestrator)
	if !ok {
		t.Fatalf("Expected BaseOrchestrator, got %T", child)
	}

	sess := childBase.Session()
	systemPrompt := sess.SystemPrompt()

	// Verify <|think|> is at the very beginning
	if !strings.HasPrefix(systemPrompt, "<|think|>") {
		t.Errorf("Expected system prompt to start with '<|think|>'")
	}

	// Verify ${{CWD}} was replaced with actual CWD
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get CWD: %v", err)
	}

	if !strings.Contains(systemPrompt, cwd) {
		t.Errorf("Expected system prompt to contain CWD '%s'", cwd)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Auditor agent type ────────────────────────────────────────────────────────

func newTestParent(t *testing.T) (*client.Client, *orchestrator.BaseOrchestrator) {
	t.Helper()
	c := client.NewClient(client.Config{BaseURL: "http://localhost:8080"})
	sess := session.New(c, "/tmp/mock.json", []client.ChatMessage{}, "parent prompt", true)
	return c, orchestrator.NewBaseOrchestrator("parent", sess, nil, 100)
}

func TestNewSubagentOrchestrator_AuditorLoadsPrompt(t *testing.T) {
	c, parent := newTestParent(t)
	enabledTools := map[string]bool{"bash": true}

	child, err := NewSubagentOrchestrator(c, "audit hotspots", []string{}, "auditor", enabledTools, false, false, 40, parent, nil, nil)
	if err != nil {
		t.Fatalf("auditor agent type returned error: %v", err)
	}

	base, ok := child.(*orchestrator.BaseOrchestrator)
	if !ok {
		t.Fatalf("expected BaseOrchestrator, got %T", child)
	}

	prompt := base.Session().SystemPrompt()
	if prompt == "" {
		t.Fatal("auditor system prompt is empty")
	}
	for _, want := range []string{"HOTSPOT_LIST", "AUDIT_COMPLETE", "Reasoning Protocol"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("auditor prompt missing expected section %q", want)
		}
	}
}

func TestNewSubagentOrchestrator_AuditorNoGemmaThinking(t *testing.T) {
	c, parent := newTestParent(t)
	enabledTools := map[string]bool{"bash": true}

	child, err := NewSubagentOrchestrator(c, "audit hotspots", []string{}, "auditor", enabledTools, false, false, 40, parent, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	base := child.(*orchestrator.BaseOrchestrator)
	prompt := base.Session().SystemPrompt()
	if strings.HasPrefix(prompt, "<|think|>") {
		t.Error("auditor prompt should not be prefixed with <|think|> when gemmaThinking=false")
	}
}

func TestNewSubagentOrchestrator_AuditorWithGemmaThinking(t *testing.T) {
	c, parent := newTestParent(t)
	enabledTools := map[string]bool{"bash": true}

	child, err := NewSubagentOrchestrator(c, "audit hotspots", []string{}, "auditor", enabledTools, false, true, 40, parent, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	base := child.(*orchestrator.BaseOrchestrator)
	prompt := base.Session().SystemPrompt()
	if !strings.HasPrefix(prompt, "<|think|>") {
		t.Error("auditor prompt should be prefixed with <|think|> when gemmaThinking=true")
	}
}

func TestNewSubagentOrchestrator_UnknownAgentTypeErrors(t *testing.T) {
	c, parent := newTestParent(t)
	enabledTools := map[string]bool{}

	_, err := NewSubagentOrchestrator(c, "goal", []string{}, "nonexistent-role", enabledTools, false, false, 10, parent, nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown agent type")
	}
	if !strings.Contains(err.Error(), "unknown agent type") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewSubagentOrchestrator_NilParentErrors(t *testing.T) {
	c := client.NewClient(client.Config{BaseURL: "http://localhost:8080"})
	_, err := NewSubagentOrchestrator(c, "goal", nil, "coder", map[string]bool{"bash": true}, false, false, 10, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error when parent orchestrator is nil")
	}
	if !strings.Contains(err.Error(), "parent orchestrator is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildSubagentMiddlewares_FactoryReplacesInherited(t *testing.T) {
	_, parent := newTestParent(t)
	parent.SetMiddlewares([]common.ToolMiddleware{
		func(next common.ToolRunner) common.ToolRunner {
			return func(_ context.Context, _ client.ToolCall) (string, error) {
				return "", context.DeadlineExceeded
			}
		},
	})

	reg := common.NewToolRegistry()
	got := buildSubagentMiddlewares(parent, reg, "coder", func(_ *common.ToolRegistry) []common.ToolMiddleware {
		return []common.ToolMiddleware{
			func(next common.ToolRunner) common.ToolRunner {
				return func(ctx context.Context, tc client.ToolCall) (string, error) {
					return next(ctx, tc)
				}
			},
		}
	})

	if len(got) != 1 {
		t.Fatalf("expected one middleware from factory replacement, got %d", len(got))
	}
}

func TestPromptPathForAgentType_NewRoles(t *testing.T) {
	tests := map[string]string{
		"strategist": "prompts/instruction-sast-strategist.md",
		"explorer":   "prompts/instruction-sast-explorer.md",
		"executor":   "prompts/instruction-sast-executor.md",
	}

	for role, want := range tests {
		got, err := promptPathForAgentType(role)
		if err != nil {
			t.Fatalf("promptPathForAgentType(%q) returned error: %v", role, err)
		}
		if got != want {
			t.Fatalf("promptPathForAgentType(%q)=%q, want %q", role, got, want)
		}
	}
}

func TestAllowToolForAgentType_StrictRoleBoundaries(t *testing.T) {
	if !allowToolForAgentType("strategist", "read_file") {
		t.Fatal("strategist should allow read_file")
	}
	if allowToolForAgentType("strategist", "search_graph") {
		t.Fatal("strategist should not allow search_graph")
	}

	for _, tool := range []string{"search_graph", "trace_path", "get_code_snippet", "query_graph", "read_file"} {
		if !allowToolForAgentType("explorer", tool) {
			t.Fatalf("explorer should allow %q", tool)
		}
	}
	if allowToolForAgentType("explorer", "bash") {
		t.Fatal("explorer should not allow bash")
	}

	for _, tool := range []string{"bash", "read_file"} {
		if !allowToolForAgentType("executor", tool) {
			t.Fatalf("executor should allow %q", tool)
		}
	}
	if allowToolForAgentType("executor", "search_graph") {
		t.Fatal("executor should not allow search_graph")
	}
}

func TestNewSubagentOrchestrator_NewRolePromptsLoad(t *testing.T) {
	c, parent := newTestParent(t)
	enabledTools := map[string]bool{"bash": true}

	tests := []struct {
		role        string
		mustContain string
	}{
		{role: "strategist", mustContain: "Head Auditor"},
		{role: "explorer", mustContain: "Codebase Navigator"},
		{role: "executor", mustContain: "sandbox PoC"},
	}

	for _, tt := range tests {
		child, err := NewSubagentOrchestrator(c, "goal", []string{}, tt.role, enabledTools, false, false, 30, parent, nil, nil)
		if err != nil {
			t.Fatalf("role %q returned error: %v", tt.role, err)
		}
		base := child.(*orchestrator.BaseOrchestrator)
		prompt := base.Session().SystemPrompt()
		if prompt == "" {
			t.Fatalf("role %q prompt is empty", tt.role)
		}
		if !strings.Contains(strings.ToLower(prompt), strings.ToLower(tt.mustContain)) {
			t.Fatalf("role %q prompt missing expected text %q", tt.role, tt.mustContain)
		}
	}
}

func TestSetupBootstrapFirstMiddleware_AllowsPreLaunchTools(t *testing.T) {
	mw := setupBootstrapFirstMiddleware()
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		return "ok", nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "bash"}}); err != nil {
		t.Fatalf("expected pre-launch tool to be allowed, got: %v", err)
	}
}

func TestSetupBootstrapFirstMiddleware_AllowsBootstrapThenOtherTools(t *testing.T) {
	mw := setupBootstrapFirstMiddleware()
	called := 0
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		called++
		return `{"status":"ok","mode_used":"compose"}`, nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "launch_docker"}}); err != nil {
		t.Fatalf("unexpected error on bootstrap call: %v", err)
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "wait_for_target_ready"}}); err != nil {
		t.Fatalf("unexpected error on readiness call: %v", err)
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "bash"}}); err != nil {
		t.Fatalf("unexpected error after bootstrap: %v", err)
	}
	if called != 3 {
		t.Fatalf("expected wrapped runner to be called three times, got %d", called)
	}
}

func TestSetupBootstrapFirstMiddleware_RequiresReadinessAfterSetupContainer(t *testing.T) {
	mw := setupBootstrapFirstMiddleware()
	runner := mw(func(_ context.Context, tc client.ToolCall) (string, error) {
		switch tc.Function.Name {
		case "setup_container":
			return `{"status":"ok"}`, nil
		case "wait_for_target_ready":
			return `{"status":"not_ready"}`, nil
		default:
			return "ok", nil
		}
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "setup_container"}}); err != nil {
		t.Fatalf("unexpected setup_container error: %v", err)
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "bash"}}); err == nil {
		t.Fatal("expected bash to be blocked until wait_for_target_ready")
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "wait_for_target_ready"}}); err != nil {
		t.Fatalf("unexpected readiness tool error: %v", err)
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "bash"}}); err != nil {
		t.Fatalf("unexpected bash error after readiness tool call: %v", err)
	}
}

func TestSetupBootstrapFirstMiddleware_NoAssetsDoesNotRequireReadiness(t *testing.T) {
	mw := setupBootstrapFirstMiddleware()
	runner := mw(func(_ context.Context, tc client.ToolCall) (string, error) {
		if tc.Function.Name == "launch_docker" {
			return `{"status":"no_docker_assets"}`, nil
		}
		return "ok", nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "launch_docker"}}); err != nil {
		t.Fatalf("unexpected launch_docker error: %v", err)
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "bash"}}); err != nil {
		t.Fatalf("expected bash to be allowed after no_docker_assets, got: %v", err)
	}
}

func TestScannerExploitReplayMiddleware_BlocksRawExploitBeforeReplay(t *testing.T) {
	mw := scannerExploitReplayMiddleware()
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		return "ok", nil
	})

	_, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "bash",
		Arguments: `{"command":"docker exec app sh -lc \"wget -qO- 'http://localhost:8080/vuln?input=test'\""}`,
	}})
	if err == nil {
		t.Fatal("expected raw exploit command to be blocked before replay")
	}
	if !strings.Contains(err.Error(), "run_exploit_replay") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScannerExploitReplayMiddleware_AllowsRawExploitAfterMatchingReplay(t *testing.T) {
	mw := scannerExploitReplayMiddleware()
	calls := 0
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		calls++
		return "ok", nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "run_exploit_replay",
		Arguments: `{"endpoint":"http://127.0.0.1:8080/vuln?input=test"}`,
	}}); err != nil {
		t.Fatalf("unexpected run_exploit_replay error: %v", err)
	}

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "bash",
		Arguments: `{"command":"docker exec app sh -lc \"wget -qO- 'http://localhost:8080/vuln?input=test'\""}`,
	}}); err != nil {
		t.Fatalf("expected raw exploit command to be allowed after replay: %v", err)
	}

	if calls != 2 {
		t.Fatalf("expected wrapped runner to be called twice, got %d", calls)
	}
}

func TestScannerExploitReplayMiddleware_BlocksCandidateMismatch(t *testing.T) {
	mw := scannerExploitReplayMiddleware()
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		return "ok", nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "run_exploit_replay",
		Arguments: `{"endpoint":"http://127.0.0.1:8080/one?input=test"}`,
	}}); err != nil {
		t.Fatalf("unexpected run_exploit_replay error: %v", err)
	}

	_, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "bash",
		Arguments: `{"command":"docker exec app sh -lc \"curl -fsS 'http://localhost:8080/two?input=test'\""}`,
	}})
	if err == nil {
		t.Fatal("expected raw exploit command with mismatched candidate to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked for candidate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScannerExploitReplayMiddleware_AllowsNonExploitBash(t *testing.T) {
	mw := scannerExploitReplayMiddleware()
	called := 0
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		called++
		return "ok", nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "bash",
		Arguments: `{"command":"echo hello"}`,
	}}); err != nil {
		t.Fatalf("expected non-exploit bash command to pass: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected wrapped runner to be called once, got %d", called)
	}
}

func TestScannerSecretsFirstMiddleware_BlocksTracePathBeforeSecretsScan(t *testing.T) {
	mw := scannerSecretsFirstMiddleware()
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		return "ok", nil
	})

	_, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "trace_path"}})
	if err == nil {
		t.Fatal("expected trace_path to be blocked before run_secrets_scanner")
	}
	if !strings.Contains(err.Error(), "run_secrets_scanner") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScannerSecretsFirstMiddleware_AllowsTracePathAfterSecretsScan(t *testing.T) {
	mw := scannerSecretsFirstMiddleware()
	called := 0
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		called++
		return "ok", nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "run_secrets_scanner"}}); err != nil {
		t.Fatalf("unexpected run_secrets_scanner error: %v", err)
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "trace_path"}}); err != nil {
		t.Fatalf("expected trace_path to be allowed after run_secrets_scanner: %v", err)
	}
	if called != 2 {
		t.Fatalf("expected wrapped runner to be called twice, got %d", called)
	}
}

func TestCleanupToolPreferredMiddleware_BlocksAdHocCleanupBash(t *testing.T) {
	mw := cleanupToolPreferredMiddleware()
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		return "ok", nil
	})

	_, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "bash",
		Arguments: `{"command":"docker compose -p scan down -v --remove-orphans"}`,
	}})
	if err == nil {
		t.Fatal("expected ad-hoc cleanup bash command to be blocked")
	}
	if !strings.Contains(err.Error(), "cleanup_scan_environment") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanupToolPreferredMiddleware_AllowsCleanupToolThenBash(t *testing.T) {
	mw := cleanupToolPreferredMiddleware()
	called := 0
	runner := mw(func(_ context.Context, _ client.ToolCall) (string, error) {
		called++
		return `{"status":"ok"}`, nil
	})

	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{Name: "cleanup_scan_environment"}}); err != nil {
		t.Fatalf("unexpected cleanup_scan_environment error: %v", err)
	}
	if _, err := runner(context.Background(), client.ToolCall{Function: client.FunctionCall{
		Name:      "bash",
		Arguments: `{"command":"docker compose -p scan down -v --remove-orphans"}`,
	}}); err != nil {
		t.Fatalf("expected bash command to be allowed after cleanup_scan_environment: %v", err)
	}
	if called != 2 {
		t.Fatalf("expected wrapped runner to be called twice, got %d", called)
	}
}
