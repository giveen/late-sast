package orchestrator

import "sync"

// Blackboard is a thread-safe key-value store for inter-agent communication.
// It implements the Blackboard architectural pattern: any agent can write
// findings (e.g. a vulnerable library discovered by the Dependency Agent) and
// other agents can read those findings to prioritise their own work (e.g. the
// Taint-Analysis Agent skipping straight to the affected entry points).
//
// A single GlobalBlackboard is provided for convenience; applications that need
// isolated namespaces can create additional instances with NewBlackboard.
type Blackboard struct {
	mu   sync.RWMutex
	data map[string]any
}

// NewBlackboard allocates an empty Blackboard.
func NewBlackboard() *Blackboard {
	return &Blackboard{data: make(map[string]any)}
}

// GlobalBlackboard is the shared inter-agent store for the default run.
var GlobalBlackboard = NewBlackboard()

// Write stores value under key, overwriting any previous entry.
func (b *Blackboard) Write(key string, value any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[key] = value
}

// Read returns the value for key and a boolean indicating presence.
func (b *Blackboard) Read(key string) (any, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.data[key]
	return v, ok
}

// ReadAll returns a shallow copy of all entries.
func (b *Blackboard) ReadAll() map[string]any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make(map[string]any, len(b.data))
	for k, v := range b.data {
		out[k] = v
	}
	return out
}

// Delete removes the entry for key. A no-op if key is absent.
func (b *Blackboard) Delete(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, key)
}
