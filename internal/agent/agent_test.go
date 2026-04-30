package agent

import (
	"os"
	"strings"
	"testing"

	"late/internal/client"
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
		nil,   // messenger
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
		nil,   // messenger
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
		true,  // injectCWD
		true,  // gemmaThinking
		100,   // maxTurns
		parent,
		nil,   // messenger
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

	child, err := NewSubagentOrchestrator(c, "audit hotspots", []string{}, "auditor", enabledTools, false, false, 40, parent, nil)
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

	child, err := NewSubagentOrchestrator(c, "audit hotspots", []string{}, "auditor", enabledTools, false, false, 40, parent, nil)
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

	child, err := NewSubagentOrchestrator(c, "audit hotspots", []string{}, "auditor", enabledTools, false, true, 40, parent, nil)
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

	_, err := NewSubagentOrchestrator(c, "goal", []string{}, "nonexistent-role", enabledTools, false, false, 10, parent, nil)
	if err == nil {
		t.Fatal("expected error for unknown agent type")
	}
	if !strings.Contains(err.Error(), "unknown agent type") {
		t.Errorf("unexpected error message: %v", err)
	}
}
