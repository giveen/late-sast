package debug

import (
	"fmt"
	"io"
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

func TestLogger_LogOperatorError_enabled(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)

	// Capture stderr.
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	testErr := fmt.Errorf("disk full")
	l.LogOperatorError("test_component", "something failed", testErr, map[string]interface{}{"key": "val"})

	w.Close()
	os.Stderr = origStderr
	var buf strings.Builder
	io.Copy(&buf, r) //nolint:errcheck

	// stderr must contain the [operator-error] prefix, component, and message.
	stderr := buf.String()
	for _, want := range []string{"[operator-error]", "test_component", "something failed", "disk full"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q; got: %s", want, stderr)
		}
	}

	// Log file must contain an OPERATOR_ERROR event with the component field.
	b, err := os.ReadFile(l.FilePath())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	s := string(b)
	for _, want := range []string{"\"event\": \"OPERATOR_ERROR\"", "\"component\": \"test_component\"", "\"message\": \"something failed\""} {
		if !strings.Contains(s, want) {
			t.Errorf("log missing %q; got: %s", want, s)
		}
	}
}

func TestLogger_LogOperatorError_disabled_still_writes_stderr(t *testing.T) {
	// A nil/disabled logger must still emit to stderr.
	l := &Logger{enabled: false}

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	l.LogOperatorError("comp", "msg", fmt.Errorf("oh no"), nil)

	w.Close()
	os.Stderr = origStderr
	var buf strings.Builder
	io.Copy(&buf, r) //nolint:errcheck

	if !strings.Contains(buf.String(), "[operator-error]") {
		t.Errorf("expected [operator-error] in stderr from disabled logger; got: %s", buf.String())
	}
}
