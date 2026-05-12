package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// WorktreeInfo contains information about a git worktree
type WorktreeInfo struct {
	Path       string
	Branch     string
	IsDetached bool
	Status     string
}

var (
	// worktreePattern matches: /path/to/worktree  commitHash [branchName]
	worktreePattern = regexp.MustCompile(`^(\S+)\s+[a-f0-9]+\s+\[([^\]]*)\]`)
	// detachedPattern matches: /path/to/worktree  commitHash (detached HEAD)
	detachedPattern = regexp.MustCompile(`^(\S+)\s+([a-f0-9]+)\s+\(detached HEAD\)`)
)

// parseWorktreeLines parses the output lines of `git worktree list` into
// WorktreeInfo structs. It handles both normal branch worktrees and
// detached-HEAD worktrees.
func parseWorktreeLines(lines []string) []WorktreeInfo {
	var worktrees []WorktreeInfo
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		var info WorktreeInfo
		if m := worktreePattern.FindStringSubmatch(line); m != nil {
			info = WorktreeInfo{Path: m[1], Branch: m[2]}
		} else if m := detachedPattern.FindStringSubmatch(line); m != nil {
			info = WorktreeInfo{Path: m[1], Branch: m[2], IsDetached: true}
		} else {
			continue
		}
		if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "# ") {
			info.Status = strings.TrimPrefix(lines[i+1], "# ")
			i++
		}
		worktrees = append(worktrees, info)
	}
	return worktrees
}

// ListWorktrees executes `git worktree list` and parses the output
// to return a slice of WorktreeInfo structures.
func ListWorktrees(ctx context.Context) ([]WorktreeInfo, error) {
	cmd := exec.CommandContext(ctx, "git", "worktree", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	return parseWorktreeLines(lines), nil
}

// CreateWorktree executes `git worktree add <path> <branch>` to create a new worktree.
func CreateWorktree(ctx context.Context, path, branch string) error {
	cmd := exec.CommandContext(ctx, "git", "worktree", "add", path, branch)
	if out, err := cmd.CombinedOutput(); err != nil {
		if len(out) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}

// RemoveWorktree executes `git worktree remove <path>` to remove a worktree.
func RemoveWorktree(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, "git", "worktree", "remove", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		if len(out) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}

// GetActiveWorktree returns the current worktree path by comparing
// the current working directory with the paths from `git worktree list`.
// If no matching worktree is found, it returns the main repository path.
func GetActiveWorktree(ctx context.Context) (string, error) {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Resolve symlinks so we compare canonical paths.
	cwdReal, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		cwdReal = cwd // fall back to raw path if resolution fails
	}

	// Get all worktrees
	worktrees, err := ListWorktrees(ctx)
	if err != nil {
		return "", err
	}

	// Compare CWD with worktree paths
	for _, wt := range worktrees {
		wtReal, err := filepath.EvalSymlinks(wt.Path)
		if err != nil {
			wtReal = wt.Path
		}
		if wtReal == cwdReal {
			return wt.Path, nil
		}
	}

	// If no match found, return the main repository path
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
