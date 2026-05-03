package orchestrator

import "sync"

const (
	BlackboardKeyExploitHistory    = "exploit_history"
	BlackboardKeyStrategistRules   = "strategist_constraints"
	BlackboardKeyCurrentHypothesis = "current_hypothesis"
	BlackboardKeyExplorerEvidence  = "explorer_evidence"
	BlackboardKeyLatestExecAttempt = "latest_executor_attempt"
)

// ExploitHistoryEntry is the structured feedback contract written by executor
// attempts and consumed by strategist planning turns.
type ExploitHistoryEntry struct {
	Turn                 int    `json:"turn"`
	AttemptID            string `json:"attempt_id"`
	Outcome              string `json:"outcome"` // SUCCESS | FAILED | UNREACHABLE
	Reason               string `json:"reason"`
	SandboxLogs          string `json:"sandbox_logs,omitempty"`
	StrategistConstraint string `json:"strategist_constraint,omitempty"`
}

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

// AppendExploitHistory appends one executor attempt result to exploit_history.
func (b *Blackboard) AppendExploitHistory(entry ExploitHistoryEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var history []ExploitHistoryEntry
	if v, ok := b.data[BlackboardKeyExploitHistory]; ok {
		if cast, ok := v.([]ExploitHistoryEntry); ok {
			history = cast
		}
	}
	history = append(history, entry)
	b.data[BlackboardKeyExploitHistory] = history
	b.data[BlackboardKeyLatestExecAttempt] = entry

	if entry.StrategistConstraint != "" {
		var constraints []string
		if v, ok := b.data[BlackboardKeyStrategistRules]; ok {
			if cast, ok := v.([]string); ok {
				constraints = cast
			}
		}
		exists := false
		for _, c := range constraints {
			if c == entry.StrategistConstraint {
				exists = true
				break
			}
		}
		if !exists {
			constraints = append(constraints, entry.StrategistConstraint)
			b.data[BlackboardKeyStrategistRules] = constraints
		}
	}
}

// ExploitHistory returns a copy of exploit_history.
func (b *Blackboard) ExploitHistory() []ExploitHistoryEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	v, ok := b.data[BlackboardKeyExploitHistory]
	if !ok {
		return nil
	}
	history, ok := v.([]ExploitHistoryEntry)
	if !ok {
		return nil
	}
	out := make([]ExploitHistoryEntry, len(history))
	copy(out, history)
	return out
}

// StrategistConstraints returns a copy of accumulated strategist constraints.
func (b *Blackboard) StrategistConstraints() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	v, ok := b.data[BlackboardKeyStrategistRules]
	if !ok {
		return nil
	}
	constraints, ok := v.([]string)
	if !ok {
		return nil
	}
	out := make([]string, len(constraints))
	copy(out, constraints)
	return out
}

// AddStrategistConstraint appends a unique strategist constraint.
func (b *Blackboard) AddStrategistConstraint(constraint string) {
	if constraint == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	var constraints []string
	if v, ok := b.data[BlackboardKeyStrategistRules]; ok {
		if cast, ok := v.([]string); ok {
			constraints = cast
		}
	}
	for _, c := range constraints {
		if c == constraint {
			return
		}
	}
	b.data[BlackboardKeyStrategistRules] = append(constraints, constraint)
}

// SetCurrentHypothesis stores the currently selected strategist hypothesis.
func (b *Blackboard) SetCurrentHypothesis(hypothesis string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[BlackboardKeyCurrentHypothesis] = hypothesis
}

// CurrentHypothesis returns the current strategist hypothesis.
func (b *Blackboard) CurrentHypothesis() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.data[BlackboardKeyCurrentHypothesis]
	if !ok {
		return ""
	}
	h, _ := v.(string)
	return h
}

// SetExplorerEvidence stores the latest explorer evidence payload.
func (b *Blackboard) SetExplorerEvidence(evidence string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[BlackboardKeyExplorerEvidence] = evidence
}

// ExplorerEvidence returns the latest explorer evidence payload.
func (b *Blackboard) ExplorerEvidence() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.data[BlackboardKeyExplorerEvidence]
	if !ok {
		return ""
	}
	e, _ := v.(string)
	return e
}

// LatestExecutorAttempt returns the last executor attempt if available.
func (b *Blackboard) LatestExecutorAttempt() (ExploitHistoryEntry, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.data[BlackboardKeyLatestExecAttempt]
	if !ok {
		return ExploitHistoryEntry{}, false
	}
	entry, ok := v.(ExploitHistoryEntry)
	if !ok {
		return ExploitHistoryEntry{}, false
	}
	return entry, true
}

// ResetExploitState clears strategist/explorer/executor mission state.
func (b *Blackboard) ResetExploitState() {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, BlackboardKeyExploitHistory)
	delete(b.data, BlackboardKeyStrategistRules)
	delete(b.data, BlackboardKeyCurrentHypothesis)
	delete(b.data, BlackboardKeyExplorerEvidence)
	delete(b.data, BlackboardKeyLatestExecAttempt)
}
