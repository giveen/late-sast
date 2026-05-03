package orchestrator

import "testing"

func TestBlackboardExploitHistoryHelpers(t *testing.T) {
	b := NewBlackboard()

	b.AppendExploitHistory(ExploitHistoryEntry{
		Turn:                 1,
		AttemptID:            "attempt-1",
		Outcome:              "FAILED",
		Reason:               "missing auth",
		StrategistConstraint: "Do not retry without auth token",
	})
	b.AppendExploitHistory(ExploitHistoryEntry{
		Turn:                 2,
		AttemptID:            "attempt-2",
		Outcome:              "UNREACHABLE",
		Reason:               "service timeout",
		StrategistConstraint: "Do not retry without auth token",
	})

	history := b.ExploitHistory()
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}
	if history[0].AttemptID != "attempt-1" || history[1].AttemptID != "attempt-2" {
		t.Fatalf("unexpected history order: %+v", history)
	}

	constraints := b.StrategistConstraints()
	if len(constraints) != 1 {
		t.Fatalf("expected deduped strategist constraints (1), got %d", len(constraints))
	}
	if constraints[0] != "Do not retry without auth token" {
		t.Fatalf("unexpected strategist constraint: %q", constraints[0])
	}
}

func TestBlackboardExploitHistoryReturnsCopy(t *testing.T) {
	b := NewBlackboard()
	b.AppendExploitHistory(ExploitHistoryEntry{AttemptID: "attempt-1"})

	history := b.ExploitHistory()
	history[0].AttemptID = "mutated"

	again := b.ExploitHistory()
	if again[0].AttemptID != "attempt-1" {
		t.Fatalf("expected internal history to remain unchanged, got %q", again[0].AttemptID)
	}
}

func TestBlackboardMissionStateHelpers(t *testing.T) {
	b := NewBlackboard()

	b.SetCurrentHypothesis("auth bypass via header confusion")
	if got := b.CurrentHypothesis(); got != "auth bypass via header confusion" {
		t.Fatalf("unexpected hypothesis: %q", got)
	}

	b.SetExplorerEvidence(`{"outcome":"PATH_FOUND"}`)
	if got := b.ExplorerEvidence(); got != `{"outcome":"PATH_FOUND"}` {
		t.Fatalf("unexpected explorer evidence: %q", got)
	}

	b.AddStrategistConstraint("do not retry same payload family")
	b.AddStrategistConstraint("do not retry same payload family")
	constraints := b.StrategistConstraints()
	if len(constraints) != 1 {
		t.Fatalf("expected deduped constraints, got %d", len(constraints))
	}

	entry := ExploitHistoryEntry{AttemptID: "a-1", Outcome: "FAILED"}
	b.AppendExploitHistory(entry)
	last, ok := b.LatestExecutorAttempt()
	if !ok {
		t.Fatal("expected latest executor attempt")
	}
	if last.AttemptID != "a-1" {
		t.Fatalf("unexpected latest attempt: %+v", last)
	}

	b.ResetExploitState()
	if got := b.CurrentHypothesis(); got != "" {
		t.Fatalf("expected reset hypothesis, got %q", got)
	}
	if got := b.ExplorerEvidence(); got != "" {
		t.Fatalf("expected reset explorer evidence, got %q", got)
	}
	if len(b.ExploitHistory()) != 0 {
		t.Fatalf("expected reset exploit history")
	}
	if len(b.StrategistConstraints()) != 0 {
		t.Fatalf("expected reset strategist constraints")
	}
	if _, ok := b.LatestExecutorAttempt(); ok {
		t.Fatalf("expected no latest executor attempt after reset")
	}
}
