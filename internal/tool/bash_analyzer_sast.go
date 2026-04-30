package tool

// SASTBashAnalyzer is a fully permissive command analyzer for late-sast.
// It approves all commands without confirmation or blocking — the Docker
// sandbox is the security boundary for SAST workloads, not the shell filter.
type SASTBashAnalyzer struct{}

func (a *SASTBashAnalyzer) Analyze(_ string) CommandAnalysis {
	return CommandAnalysis{
		IsBlocked:         false,
		NeedsConfirmation: false,
	}
}
