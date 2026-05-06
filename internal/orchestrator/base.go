package orchestrator

import (
	"context"
	"late/internal/client"
	"late/internal/common"
	"late/internal/executor"
	"late/internal/session"
	"sync"
	"sync/atomic"
)

// BaseOrchestrator implements common.Orchestrator and manages an agent's run loop.
type BaseOrchestrator struct {
	id          string
	sess        *session.Session
	middlewares []common.ToolMiddleware
	eventCh     chan common.Event

	mu          sync.RWMutex
	parent      common.Orchestrator
	children    []common.Orchestrator
	coordinator *executor.ResourceCoordinator

	// Running state tracker
	acc    executor.StreamAccumulator
	ctx    context.Context
	cancel context.CancelFunc

	// rootCtx is the caller-supplied context (with injected values such as
	// SkipConfirmationKey and ToolApprovalKey). It is stored by SetContext and
	// used to reset o.ctx when a previous run's cancellable child has expired,
	// preserving those values across successive Submit/Execute calls.
	rootCtx context.Context

	// Stop mechanism
	stopCh chan struct{}

	// Max turns configuration
	maxTurns int

	// Turn counter — incremented atomically at the start of each RunLoop turn.
	turnCurrent int64

	stateMachine *StateMachine

	// sharedCache is an optional scan-session-level tool result cache shared
	// across the root orchestrator and all subagents in the same scan.
	sharedCache *executor.ToolResultCache
}

func NewBaseOrchestrator(id string, sess *session.Session, middlewares []common.ToolMiddleware, maxTurns int) *BaseOrchestrator {
	return &BaseOrchestrator{
		id:           id,
		sess:         sess,
		middlewares:  middlewares,
		eventCh:      make(chan common.Event, 100),
		ctx:          context.Background(),
		rootCtx:      context.Background(),
		stopCh:       make(chan struct{}, 1),
		maxTurns:     maxTurns,
		stateMachine: NewStateMachine(PhaseStop),
	}
}

// SetSharedCache injects a scan-session-level cache that will be passed to
// RunLoop so tool results can be reused across all turns and subagents.
func (o *BaseOrchestrator) SetSharedCache(c *executor.ToolResultCache) {
	o.mu.Lock()
	o.sharedCache = c
	o.mu.Unlock()
}

func (o *BaseOrchestrator) switchPhase(to Phase, reason string, turn int) {
	if o.stateMachine == nil {
		return
	}
	from, changed, err := o.stateMachine.SwitchState(to)
	if err != nil {
		return
	}
	if !changed {
		return
	}
	o.eventCh <- common.PhaseEvent{
		ID:     o.id,
		From:   string(from),
		To:     string(to),
		Reason: reason,
		Turn:   turn,
	}
}

func (o *BaseOrchestrator) SetMiddlewares(middlewares []common.ToolMiddleware) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.middlewares = middlewares
}

func (o *BaseOrchestrator) SetContext(ctx context.Context) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rootCtx = ctx
	o.ctx = ctx
}

func (o *BaseOrchestrator) SetMaxTurns(maxTurns int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.maxTurns = maxTurns
}

func (o *BaseOrchestrator) MaxTurns() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.maxTurns
}

// PushEvent injects an event into the orchestrator's event channel from outside
// the run loop (e.g. from main.go to deliver architecture / highlight events to
// the GUI). Non-blocking: events are dropped if the channel buffer is full.
func (o *BaseOrchestrator) PushEvent(e common.Event) {
	select {
	case o.eventCh <- e:
	default:
	}
}

// SetCoordinator attaches a ResourceCoordinator to this orchestrator.
// When set, the orchestrator serialises LLM inference through the coordinator's
// GPU mutex, releasing it between inference and tool-execution phases so that
// sibling agents can run their own inference in the meantime.
func (o *BaseOrchestrator) SetCoordinator(c *executor.ResourceCoordinator) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.coordinator = c
}

// Coordinator returns the attached ResourceCoordinator, or nil if none.
func (o *BaseOrchestrator) Coordinator() *executor.ResourceCoordinator {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.coordinator
}

func (o *BaseOrchestrator) MaxTokens() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.sess.Client().ContextSize()
}

func (o *BaseOrchestrator) RefreshContextSize(ctx context.Context) {
	o.sess.Client().RefreshContextSize(ctx)
}

func (o *BaseOrchestrator) ID() string { return o.id }

func (o *BaseOrchestrator) Submit(text string) error {
	o.mu.Lock()
	// Clear any old cancellation state so a new run isn't instantly aborted
	o.cancel = nil
	// Reset the base context if it was already cancelled, preserving any
	// caller-injected values (e.g. SkipConfirmationKey, ToolApprovalKey).
	if o.ctx.Err() != nil {
		o.ctx = o.rootCtx
	}
	// Drain any residual stop signal left by a Cancel() that arrived after the
	// previous run had already completed. Without this, IsStopRequested() at
	// the end of the new run would consume the stale signal and emit a
	// spurious StopRequestedEvent for a run that was never cancelled.
	select {
	case <-o.stopCh:
	default:
	}
	o.mu.Unlock()

	if err := o.sess.AddUserMessage(text); err != nil {
		return err
	}

	// Emit the correct initial status: "queued" when a coordinator is present
	// (the first turn will wait for the GPU lock), "thinking" otherwise.
	atomic.StoreInt64(&o.turnCurrent, 0)
	o.switchPhase(PhasePlan, "submit received", 0)
	if o.Coordinator() != nil {
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "queued"}
	} else {
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "thinking"}
	}
	// Start the run loop in a background goroutine
	go o.run()
	return nil
}

// buildRunLoopCallbacks constructs the onStartTurn / onGPUAcquired /
// onGPUReleased closures that drive the per-turn status events.
//
// When a coordinator is present:
//   - onStartTurn   → "queued"   (agent is waiting for the GPU)
//   - onGPUAcquired → "thinking" (agent now holds the GPU and is streaming)
//   - onGPUReleased → "working"  (agent released the GPU and is running tools)
//
// Without a coordinator the legacy behavior is preserved:
//   - onStartTurn  → "thinking"  (no queuing concept)
//   - onGPUAcquired / onGPUReleased → nil (never called)
func (o *BaseOrchestrator) buildRunLoopCallbacks(ctx context.Context) (
	onStartTurn func(),
	onGPUAcquired func(),
	onGPUReleased func(),
) {
	coord := o.Coordinator()

	onStartTurn = func() {
		o.RefreshContextSize(ctx)
		o.mu.Lock()
		o.acc.Reset()
		mt := o.maxTurns
		o.mu.Unlock()
		turn := int(atomic.AddInt64(&o.turnCurrent, 1))
		o.switchPhase(PhasePlan, "turn start", turn)
		if coord != nil {
			o.eventCh <- common.StatusEvent{ID: o.id, Status: "queued", Turn: turn, MaxTurns: mt}
		} else {
			o.eventCh <- common.StatusEvent{ID: o.id, Status: "thinking", Turn: turn, MaxTurns: mt}
		}
	}

	if coord != nil {
		onGPUAcquired = func() {
			o.switchPhase(PhaseExplore, "llm stream acquired", int(atomic.LoadInt64(&o.turnCurrent)))
			o.eventCh <- common.StatusEvent{ID: o.id, Status: "thinking"}
		}
	}

	onGPUReleased = func() {
		o.switchPhase(PhaseExecute, "tool execution", int(atomic.LoadInt64(&o.turnCurrent)))
		if coord != nil {
			o.eventCh <- common.StatusEvent{ID: o.id, Status: "working"}
		}
	}

	return onStartTurn, onGPUAcquired, onGPUReleased
}

// prepareContext resets the orchestrator context if it has expired, creates a
// cancellable child, stores the cancel func, and injects the orchestrator ID
// for tool interactions. The caller must defer the returned cancel.
func (o *BaseOrchestrator) prepareContext() (context.Context, context.CancelFunc) {
	o.mu.Lock()
	if o.ctx.Err() != nil {
		o.ctx = o.rootCtx
	}
	ctx, cancel := context.WithCancel(o.ctx)
	o.cancel = cancel
	o.ctx = ctx
	o.mu.Unlock()
	return context.WithValue(ctx, common.OrchestratorIDKey, o.id), cancel
}

// doRunLoop builds all shared RunLoop callbacks and runs the inference/tool
// loop to completion. It resets the stream accumulator on exit.
// Initial and terminal status events are the caller's responsibility.
func (o *BaseOrchestrator) doRunLoop(ctx context.Context) (string, error) {
	var extraBody map[string]any

	onStartTurn, onGPUAcquired, onGPUReleased := o.buildRunLoopCallbacks(ctx)

	onEndTurn := func() {
		o.RefreshContextSize(ctx)
		o.mu.Lock()
		usage := o.acc.Usage
		o.acc.Reset()
		o.mu.Unlock()
		o.switchPhase(PhaseFeedback, "turn completed", int(atomic.LoadInt64(&o.turnCurrent)))
		o.eventCh <- common.ContentEvent{ID: o.id, Usage: usage}
	}

	res, err := executor.RunLoop(
		ctx,
		o.sess,
		o.maxTurns,
		extraBody,
		onStartTurn,
		onEndTurn,
		func(sr common.StreamResult) {
			o.mu.Lock()
			o.acc.Append(sr)
			accCopy := o.acc
			o.mu.Unlock()
			o.eventCh <- common.ContentEvent{
				ID:               o.id,
				Content:          accCopy.Content,
				ReasoningContent: accCopy.Reasoning,
				ToolCalls:        accCopy.ToolCalls,
				Usage:            accCopy.Usage,
			}
		},
		o.middlewares,
		o.Coordinator(),
		onGPUAcquired,
		onGPUReleased,
		func(toolName string, running bool) {
			o.eventCh <- common.ToolRuntimeEvent{ID: o.id, Tool: toolName, Running: running}
		},
		o.sharedCache,
	)

	o.mu.Lock()
	o.acc.Reset()
	o.mu.Unlock()

	return res, err
}

func (o *BaseOrchestrator) Execute(text string) (string, error) {
	ctx, cancel := o.prepareContext()
	defer cancel()

	if err := o.sess.AddUserMessage(text); err != nil {
		return "", err
	}

	atomic.StoreInt64(&o.turnCurrent, 0)
	o.switchPhase(PhasePlan, "execute invoked", 0)
	if o.Coordinator() != nil {
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "queued"}
	} else {
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "thinking"}
	}
	defer func() { o.eventCh <- common.StatusEvent{ID: o.id, Status: "idle"} }()

	res, err := o.doRunLoop(ctx)
	if err != nil {
		o.switchPhase(PhaseStop, "run errored", int(atomic.LoadInt64(&o.turnCurrent)))
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "error", Error: err}
	} else {
		o.switchPhase(PhaseStop, "run closed", int(atomic.LoadInt64(&o.turnCurrent)))
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "closed"}
	}
	return res, err
}

func (o *BaseOrchestrator) run() {
	ctx, cancel := o.prepareContext()
	defer cancel()

	_, err := o.doRunLoop(ctx)
	if err != nil {
		o.switchPhase(PhaseStop, "run errored", int(atomic.LoadInt64(&o.turnCurrent)))
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "error", Error: err}
	} else {
		o.switchPhase(PhaseStop, "run idle", int(atomic.LoadInt64(&o.turnCurrent)))
		o.eventCh <- common.StatusEvent{ID: o.id, Status: "idle"}
	}

	if o.IsStopRequested() {
		o.eventCh <- common.StopRequestedEvent{ID: o.id}
	}
}

func (o *BaseOrchestrator) Events() <-chan common.Event {
	return o.eventCh
}

func (o *BaseOrchestrator) Cancel() {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.cancel != nil {
		o.cancel()
	}

	select {
	case o.stopCh <- struct{}{}:
		// Signal sent
	default:
		// Already signaled, ignore
	}
}

func (o *BaseOrchestrator) IsStopRequested() bool {
	select {
	case <-o.stopCh:
		return true
	default:
		return false
	}
}

func (o *BaseOrchestrator) History() []client.ChatMessage {
	return o.sess.History
}

func (o *BaseOrchestrator) Session() *session.Session {
	return o.sess
}

func (o *BaseOrchestrator) SystemPrompt() string {
	return o.sess.SystemPrompt()
}

func (o *BaseOrchestrator) ToolDefinitions() []client.ToolDefinition {
	return o.sess.GetToolDefinitions()
}

func (o *BaseOrchestrator) Context() context.Context {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.ctx
}

func (o *BaseOrchestrator) Middlewares() []common.ToolMiddleware {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.middlewares
}

func (o *BaseOrchestrator) Registry() *common.ToolRegistry {
	return o.sess.Registry
}

func (o *BaseOrchestrator) Children() []common.Orchestrator {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.children
}

func (o *BaseOrchestrator) Parent() common.Orchestrator {
	return o.parent
}

func (o *BaseOrchestrator) Reset() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sess.History = []client.ChatMessage{}
	return session.SaveHistory(o.sess.HistoryPath, nil)
}

func (o *BaseOrchestrator) AddChild(child common.Orchestrator, agentType string) {
	o.mu.Lock()
	o.children = append(o.children, child)
	o.mu.Unlock()

	o.eventCh <- common.ChildAddedEvent{
		ParentID:  o.id,
		Child:     child,
		AgentType: agentType,
	}
}
