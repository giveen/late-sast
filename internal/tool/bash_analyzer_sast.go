package tool

import (
	"fmt"
	"regexp"
	"strconv"
)

// SASTBashAnalyzer is a fully permissive command analyzer for late-sast.
// It approves all commands without confirmation or blocking — the Docker
// sandbox is the security boundary for SAST workloads, not the shell filter.
type SASTBashAnalyzer struct{}

var sleepRe = regexp.MustCompile(`(?i)\bsleep\s+(\d+)\b`)

const (
	maxSingleSleepSeconds = 15
	maxTotalSleepSeconds  = 90
)

func (a *SASTBashAnalyzer) Analyze(command string) CommandAnalysis {
	matches := sleepRe.FindAllStringSubmatch(command, -1)
	totalSleep := 0
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		sec, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if sec > maxSingleSleepSeconds {
			return CommandAnalysis{
				IsBlocked:         true,
				NeedsConfirmation: false,
				BlockReason:       fmt.Errorf("sleep %ds exceeds SAST runtime limit of %ds; use bounded polling intervals", sec, maxSingleSleepSeconds),
			}
		}
		totalSleep += sec
	}
	if totalSleep > maxTotalSleepSeconds {
		return CommandAnalysis{
			IsBlocked:         true,
			NeedsConfirmation: false,
			BlockReason:       fmt.Errorf("cumulative sleep %ds exceeds SAST runtime limit of %ds; use bounded polling", totalSleep, maxTotalSleepSeconds),
		}
	}

	return CommandAnalysis{
		IsBlocked:         false,
		NeedsConfirmation: false,
	}
}
