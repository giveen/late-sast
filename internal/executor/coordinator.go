package executor

import (
	"context"
	"fmt"
)

// ResourceCoordinator serializes LLM inference across concurrent agents.
// Because a single local GPU can only run one forward pass at a time, every
// agent must hold the GPU lock for the duration of its HTTP stream and release
// it before executing shell/tool calls. This lets other agents "Work" (run
// Docker, shell commands, API calls) while the GPU is busy with inference for
// the current agent.
//
// The implementation uses a channel semaphore so that AcquireGPULock respects
// context cancellation — a goroutine waiting for the GPU will unblock
// immediately when its context is cancelled rather than blocking indefinitely.
//
// Usage:
//
//	coord := executor.GlobalGPU
//	if err := coord.AcquireGPULock(ctx); err != nil {
//	    return err // context was cancelled while waiting
//	}
//	... stream from LLM ...
//	coord.ReleaseGPULock() // releases so next agent can think
//	... run tool calls without holding the lock ...
type ResourceCoordinator struct {
	ch chan struct{}
}

// newResourceCoordinator allocates a coordinator with one GPU slot.
func newResourceCoordinator() *ResourceCoordinator {
	ch := make(chan struct{}, 1)
	ch <- struct{}{} // one token = GPU is free
	return &ResourceCoordinator{ch: ch}
}

// GlobalGPU is the default coordinator. Applications sharing a single local
// GPU should pass this instance to every orchestrator via SetCoordinator.
var GlobalGPU = newResourceCoordinator()

// AcquireGPULock blocks until the GPU is available for inference or until ctx
// is cancelled. Returns a non-nil error if the context was cancelled before
// the lock was acquired. The caller MUST call ReleaseGPULock on success.
func (r *ResourceCoordinator) AcquireGPULock(ctx context.Context) error {
	select {
	case <-r.ch:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("GPU lock acquisition cancelled: %w", ctx.Err())
	}
}

// ReleaseGPULock frees the GPU so the next waiting agent can begin inference.
// Panics if called without a preceding successful AcquireGPULock (analogous
// to sync.Mutex.Unlock on an already-unlocked mutex).
func (r *ResourceCoordinator) ReleaseGPULock() {
	select {
	case r.ch <- struct{}{}:
		// token returned; GPU is free again
	default:
		panic("executor.ResourceCoordinator: ReleaseGPULock called without matching AcquireGPULock")
	}
}
