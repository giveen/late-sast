package orchestrator

import (
	"fmt"
	"sync"
)

// Phase is the high-level orchestrator state.
type Phase string

const (
	PhasePlan     Phase = "PLAN"
	PhaseExplore  Phase = "EXPLORE"
	PhaseExecute  Phase = "EXECUTE"
	PhaseFeedback Phase = "FEEDBACK"
	PhaseStop     Phase = "STOP"
)

var allowedTransitions = map[Phase]map[Phase]bool{
	PhaseStop: {
		PhaseStop: true,
		PhasePlan: true,
	},
	PhasePlan: {
		PhasePlan:    true,
		PhaseExplore: true,
		PhaseExecute: true,
		PhaseStop:    true,
	},
	PhaseExplore: {
		PhaseExplore: true,
		PhasePlan:    true,
		PhaseStop:    true,
	},
	PhaseExecute: {
		PhaseExecute:  true,
		PhaseFeedback: true,
		PhaseStop:     true,
	},
	PhaseFeedback: {
		PhaseFeedback: true,
		PhasePlan:     true,
		PhaseStop:     true,
	},
}

// StateMachine tracks and validates phase transitions.
type StateMachine struct {
	mu    sync.RWMutex
	phase Phase
}

func NewStateMachine(initial Phase) *StateMachine {
	return &StateMachine{phase: initial}
}

func (s *StateMachine) Current() Phase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phase
}

// SwitchState transitions to newPhase if allowed.
// Returns (from, changed, error).
func (s *StateMachine) SwitchState(newPhase Phase) (Phase, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	from := s.phase
	if from == newPhase {
		return from, false, nil
	}

	allowed, ok := allowedTransitions[from]
	if !ok || !allowed[newPhase] {
		return from, false, fmt.Errorf("invalid state transition: %s -> %s", from, newPhase)
	}

	s.phase = newPhase
	return from, true, nil
}
