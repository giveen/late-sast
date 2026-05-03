package orchestrator

import "testing"

func TestStateMachineValidTransitions(t *testing.T) {
	sm := NewStateMachine(PhaseStop)

	if _, changed, err := sm.SwitchState(PhasePlan); err != nil || !changed {
		t.Fatalf("expected STOP -> PLAN to succeed, changed=%v err=%v", changed, err)
	}
	if _, changed, err := sm.SwitchState(PhaseExplore); err != nil || !changed {
		t.Fatalf("expected PLAN -> EXPLORE to succeed, changed=%v err=%v", changed, err)
	}
	if _, changed, err := sm.SwitchState(PhasePlan); err != nil || !changed {
		t.Fatalf("expected EXPLORE -> PLAN to succeed, changed=%v err=%v", changed, err)
	}
	if _, changed, err := sm.SwitchState(PhaseExecute); err != nil || !changed {
		t.Fatalf("expected PLAN -> EXECUTE to succeed, changed=%v err=%v", changed, err)
	}
	if _, changed, err := sm.SwitchState(PhaseFeedback); err != nil || !changed {
		t.Fatalf("expected EXECUTE -> FEEDBACK to succeed, changed=%v err=%v", changed, err)
	}
	if _, changed, err := sm.SwitchState(PhaseStop); err != nil || !changed {
		t.Fatalf("expected FEEDBACK -> STOP to succeed, changed=%v err=%v", changed, err)
	}
}

func TestStateMachineInvalidTransition(t *testing.T) {
	sm := NewStateMachine(PhaseStop)

	from, changed, err := sm.SwitchState(PhaseExecute)
	if err == nil {
		t.Fatalf("expected invalid transition error")
	}
	if changed {
		t.Fatalf("expected changed=false on invalid transition")
	}
	if from != PhaseStop {
		t.Fatalf("expected from phase STOP, got %s", from)
	}
	if sm.Current() != PhaseStop {
		t.Fatalf("expected current phase to remain STOP, got %s", sm.Current())
	}
}
