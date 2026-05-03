package executor

import "sync"

// ResourceCoordinator serializes LLM inference across concurrent agents.
// Because a single local GPU can only run one forward pass at a time, every
// agent must hold the GPU lock for the duration of its HTTP stream and release
// it before executing shell/tool calls. This lets other agents "Work" (run
// Docker, shell commands, API calls) while the GPU is busy with inference for
// the current agent.
//
// Usage:
//
//	coord := executor.GlobalGPU
//	coord.AcquireGPULock()   // blocks until the GPU is free
//	... stream from LLM ...
//	coord.ReleaseGPULock()   // releases so next agent can think
//	... run tool calls without holding the lock ...
type ResourceCoordinator struct {
	mu sync.Mutex
}

// GlobalGPU is the default coordinator. Applications sharing a single local
// GPU should pass this instance to every orchestrator via SetCoordinator.
var GlobalGPU = &ResourceCoordinator{}

// AcquireGPULock blocks until the GPU is available for inference. The caller
// MUST call ReleaseGPULock when the HTTP stream has been fully consumed.
func (r *ResourceCoordinator) AcquireGPULock() {
	r.mu.Lock()
}

// ReleaseGPULock frees the GPU so the next waiting agent can begin inference.
func (r *ResourceCoordinator) ReleaseGPULock() {
	r.mu.Unlock()
}
