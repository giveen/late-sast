package tool

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CommandRunner executes a command and returns combined stdout/stderr.
// It is used as a dependency-injection seam in container lifecycle tools
// so that tests can substitute a fake runner without shelling out.
type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)

// RunSetupCommand is the default CommandRunner implementation. It runs
// name with args, captures combined output, and wraps exec errors with the
// command invocation for easier diagnosis.
func RunSetupCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}

// ShQuote wraps s in single-quotes, escaping any embedded single-quotes
// so the result is safe to embed in a POSIX shell command string.
func ShQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
