package common

import (
	"context"
	"encoding/json"
	"late/internal/client"
)

// ToolRunner defines the functional signature for executing a single tool call.
type ToolRunner func(ctx context.Context, tc client.ToolCall) (string, error)

// ToolMiddleware wraps a ToolRunner, allowing interception of tool execution.
type ToolMiddleware func(next ToolRunner) ToolRunner

// Orchestrator defines the interface for an agentic conversation manager.
type Orchestrator interface {
	ID() string
	Submit(text string) error
	Execute(text string) (string, error)
	Reset() error
	Cancel()
	Events() <-chan Event
	History() []client.ChatMessage
	Context() context.Context
	Middlewares() []ToolMiddleware
	Registry() *ToolRegistry
	SystemPrompt() string
	ToolDefinitions() []client.ToolDefinition

	// Hierarchy
	Children() []Orchestrator
	Parent() Orchestrator

	// Configuration
	SetMaxTurns(int)
	MaxTurns() int
	RefreshContextSize(context.Context)
	MaxTokens() int
}

// Event represents something that happened in the orchestrator.
type Event interface {
	OrchestratorID() string
}

// ContentEvent is sent when content or reasoning is streamed.
type ContentEvent struct {
	ID               string
	Content          string
	ReasoningContent string
	ToolCalls        []client.ToolCall
	Usage            client.Usage
}

func (e ContentEvent) OrchestratorID() string { return e.ID }

// ChildAddedEvent is sent when a new subagent is spawned.
type ChildAddedEvent struct {
	ParentID  string
	Child     Orchestrator
	AgentType string // e.g. "scanner", "coder", "auditor"
}

func (e ChildAddedEvent) OrchestratorID() string { return e.ParentID }

// StatusEvent is sent when the orchestrator's state changes.
type StatusEvent struct {
	ID       string
	Status   string // "thinking", "idle", "error", etc.
	Error    error  // Optional error info
	Turn     int    // Optional: current turn index (1-based)
	MaxTurns int    // Optional: orchestrator max-turn budget for this run
}

func (e StatusEvent) OrchestratorID() string { return e.ID }

// PhaseEvent is sent when the orchestrator's higher-level state machine
// transitions between execution phases.
type PhaseEvent struct {
	ID     string
	From   string // PLAN, EXPLORE, EXECUTE, FEEDBACK, STOP
	To     string // PLAN, EXPLORE, EXECUTE, FEEDBACK, STOP
	Reason string // Optional transition reason
	Turn   int    // Optional turn index when the transition occurred
}

func (e PhaseEvent) OrchestratorID() string { return e.ID }

// MissionSnapshotEvent carries strategist-loop state projected from the
// blackboard for compact live display in the GUI.
type MissionSnapshotEvent struct {
	OrcID               string
	CurrentHypothesis   string
	LastExecutorOutcome string
	LastExecutorReason  string
	ActiveConstraints   []string
}

func (e MissionSnapshotEvent) OrchestratorID() string { return e.OrcID }

// StopRequestedEvent is sent when a stop is requested for an orchestrator.
type StopRequestedEvent struct {
	ID string
}

func (e StopRequestedEvent) OrchestratorID() string { return e.ID }

// NodeHighlightEvent is sent when an agent accesses a file or graph node,
// triggering a real-time visual highlight in the Project Map tab.
type NodeHighlightEvent struct {
	OrcID     string
	FilePath  string // The file path or graph node being accessed
	IsHotspot bool   // Whether this node is a known security hotspot
}

func (e NodeHighlightEvent) OrchestratorID() string { return e.OrcID }

// ArchitectureCluster represents a logical grouping of files detected by
// Louvain community detection in codebase-memory-mcp.
type ArchitectureCluster struct {
	ID        string
	Label     string
	Files     []string
	IsHotspot bool
}

// ArchitectureData is a parsed summary of the get_architecture MCP response.
type ArchitectureData struct {
	Clusters  []ArchitectureCluster
	Hotspots  []string // File paths / node IDs of hotspots
	Language  string
	FileCount int
	NodeCount int
	EdgeCount int
}

// ProjectMapLoadedEvent carries the architecture data used to populate the
// "Project Map" GUI tab. Emitted once per scan after get_architecture succeeds.
type ProjectMapLoadedEvent struct {
	OrcID string
	Data  ArchitectureData
}

func (e ProjectMapLoadedEvent) OrchestratorID() string { return e.OrcID }

// PromptRequest defines a generic requirement for user input.
type PromptRequest struct {
	ID          string
	Title       string
	Description string
	Schema      json.RawMessage // JSON Schema for validation
}

// InputProvider is the abstract capability tools use to get user data.
type InputProvider interface {
	Prompt(ctx context.Context, req PromptRequest) (json.RawMessage, error)
}

// Context keys
type contextKey string

const (
	InputProviderKey    contextKey = "input_provider"
	OrchestratorIDKey   contextKey = "orchestrator_id"
	SkipConfirmationKey contextKey = "skip_confirmation"
	ToolApprovalKey     contextKey = "tool_approval"
)

// GetInputProvider returns the InputProvider from the context.
func GetInputProvider(ctx context.Context) InputProvider {
	if p, ok := ctx.Value(InputProviderKey).(InputProvider); ok {
		return p
	}
	return nil
}

// GetOrchestratorID returns the Orchestrator ID from the context.
func GetOrchestratorID(ctx context.Context) string {
	if id, ok := ctx.Value(OrchestratorIDKey).(string); ok {
		return id
	}
	return ""
}
