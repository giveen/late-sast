package orchestrator

import (
	"strings"
	"time"
)

const (
	DefaultMaxTurnsCeiling   = 500
	DefaultMaxTimeoutCeiling = 60 * time.Minute

	FallbackSubagentTurns   = 150
	FallbackSubagentTimeout = 15 * time.Minute
)

// languageMultipliers maps normalised language names to turn-budget multipliers.
// C/C++ requires more turns due to deep call stacks and manual memory complexity.
// Python/JavaScript are typically flatter and can be audited with fewer turns.
var languageMultipliers = map[string]float64{
	"c":          1.5,
	"cpp":        1.5,
	"c++":        1.5,
	"rust":       1.3,
	"go":         1.0,
	"java":       1.0,
	"csharp":     1.0,
	"c#":         1.0,
	"kotlin":     1.0,
	"swift":      1.0,
	"typescript": 0.9,
	"python":     0.8,
	"javascript": 0.8,
	"php":        0.8,
	"ruby":       0.8,
}

// LanguageMultiplier returns the turn-budget multiplier for the given language.
// Unrecognised languages return 1.0 (no change).
func LanguageMultiplier(language string) float64 {
	if m, ok := languageMultipliers[strings.ToLower(language)]; ok {
		return m
	}
	return 1.0
}

// ComplexityMeta is the architecture metadata consumed by the heuristic engine.
type ComplexityMeta struct {
	FileCount       int
	NodeCount       int
	RouteCount      int
	HotspotCount    int
	PrimaryLanguage string // e.g. "go", "python", "c++"
}

// CalculateTurns returns a dynamic turn budget based on codebase complexity.
// Formula: (50 + 5*routeCount + 10*hotspotCount) × languageMultiplier, capped at maxTurnsCeiling.
func CalculateTurns(meta ComplexityMeta, maxTurnsCeiling int) int {
	base := 50 + (5 * meta.RouteCount) + (10 * meta.HotspotCount)

	if meta.PrimaryLanguage != "" {
		mult := LanguageMultiplier(meta.PrimaryLanguage)
		base = int(float64(base) * mult)
	}

	if maxTurnsCeiling <= 0 {
		maxTurnsCeiling = DefaultMaxTurnsCeiling
	}
	if base > maxTurnsCeiling {
		return maxTurnsCeiling
	}
	if base < 1 {
		return 1
	}
	return base
}

// CalculateTimeout returns a dynamic wall-clock timeout for a subagent.
// Formula: 5m + (2s * fileCount) + (5s * hotspotCount), capped at maxTimeoutCeiling.
func CalculateTimeout(meta ComplexityMeta, maxTimeoutCeiling time.Duration) time.Duration {
	t := 5*time.Minute + (time.Duration(meta.FileCount) * 2 * time.Second) + (time.Duration(meta.HotspotCount) * 5 * time.Second)

	if maxTimeoutCeiling <= 0 {
		maxTimeoutCeiling = DefaultMaxTimeoutCeiling
	}
	if t > maxTimeoutCeiling {
		return maxTimeoutCeiling
	}
	if t < time.Second {
		return time.Second
	}
	return t
}
