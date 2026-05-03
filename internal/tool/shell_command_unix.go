//go:build !windows

package tool

import (
	"context"
	"os/exec"
	"sync"
	"syscall"
)

var (
	unixShellPath     string
	unixShellPathOnce sync.Once
)

func getUnixShellPath() string {
	unixShellPathOnce.Do(func() {
		if shellPath, err := exec.LookPath("bash"); err == nil {
			unixShellPath = shellPath
			return
		}
		if shellPath, err := exec.LookPath("sh"); err == nil {
			unixShellPath = shellPath
			return
		}
		unixShellPath = "sh"
	})
	return unixShellPath
}

func newShellCommand(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, getUnixShellPath(), "-c", command)
}

// setProcessGroup puts cmd in its own process group so that killProcessGroup
// can send SIGKILL to the shell AND all its descendants (e.g. docker exec
// subprocesses that inherit the stdout/stderr pipes).
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup sends SIGKILL to every process in cmd's process group.
// This is needed because exec.CommandContext only kills the direct child;
// grandchildren (e.g. docker exec) keep the pipe open and CombinedOutput
// blocks indefinitely.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		// Negative PID targets the entire process group.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
