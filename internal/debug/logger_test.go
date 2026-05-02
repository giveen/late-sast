package debug

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogger_LogToolResultWithMeta(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)
	if !l.Enabled() {
		t.Fatal("logger should be enabled")
	}

	exit := 8
	l.LogToolResultWithMeta("bash", "tc_1", "Command failed with exit code 8", &ToolResultMeta{
		DurationMS:     123,
		Status:         "failed",
		Classification: "shell_exit_nonzero",
		ExitCode:       &exit,
	})

	b, err := os.ReadFile(l.FilePath())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	s := string(b)
	for _, want := range []string{"\"event\": \"TOOL_RESULT\"", "\"classification\": \"shell_exit_nonzero\"", "\"exit_code\": 8"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in log: %s", want, s)
		}
	}
}

func TestLogger_LogTurnSummary(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)

	l.LogTurnSummary(TurnSummary{
		TurnIndex:          2,
		ToolCalls:          3,
		ToolFailures:       1,
		DuplicateToolTurns: 1,
	})

	logPath := filepath.Clean(l.FilePath())
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	s := string(b)
	for _, want := range []string{"\"event\": \"TURN_SUMMARY\"", "\"turn_index\": 2", "\"tool_failures\": 1"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in log: %s", want, s)
		}
	}
}
