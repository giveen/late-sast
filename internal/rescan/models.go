// Package rescan implements incremental, lineage-aware rescan state for late-sast.
//
// Phase 1 provides deterministic source/transform keys, a persistent store, and delta
// scope computation so that subsequent scans can skip unchanged work.  Later phases will
// add artifact reconciliation, stable finding IDs, and diff-first reporting.
package rescan

import "time"

// SourceItem represents a scanned source file or item in the repository.
type SourceItem struct {
	Repo        string    `json:"repo"`
	Path        string    `json:"path"`
	ContentHash string    `json:"content_hash"`
	Commit      string    `json:"commit,omitempty"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// TransformRecord records the deterministic result of a named scan transform.
// The record is addressed by TransformKey(name, versionHash, inputHash).
type TransformRecord struct {
	RunID                string    `json:"run_id"`
	TransformName        string    `json:"transform_name"`
	TransformVersionHash string    `json:"transform_version_hash"`
	InputHash            string    `json:"input_hash"`
	OutputHash           string    `json:"output_hash"`
	Status               string    `json:"status"` // "ok" | "failed" | "skipped"
	DurationMS           int64     `json:"duration_ms"`
	CreatedAt            time.Time `json:"created_at"`
}

// RunSummary records high-level metrics for a single scan run.
type RunSummary struct {
	RunID             string    `json:"run_id"`
	StartedAt         time.Time `json:"started_at"`
	FinishedAt        time.Time `json:"finished_at"`
	SourcesTotal      int       `json:"sources_total"`
	SourcesChanged    int       `json:"sources_changed"`
	TransformsTotal   int       `json:"transforms_total"`
	TransformsSkipped int       `json:"transforms_skipped"`
	TransformsRun     int       `json:"transforms_run"`
}

// DeltaScope describes which sources and transforms need to be reprocessed
// based on what changed relative to the previous run's store state.
type DeltaScope struct {
	ChangedSources     []SourceItem
	AffectedTransforms []string
}

// FindingStatus records how a finding's state changed relative to the last run.
type FindingStatus string

const (
	FindingNew       FindingStatus = "new"
	FindingUpdated   FindingStatus = "updated"   // severity or verdict changed
	FindingResolved  FindingStatus = "resolved"  // present before, absent now
	FindingUnchanged FindingStatus = "unchanged" // identical to prior run
)

// FindingRecord is the persisted representation of a security finding.
// Its identity is the stable ID returned by FindingID(cwe, location, title).
type FindingRecord struct {
	ID             string        `json:"id"` // FindingID(cwe, location, title)
	Title          string        `json:"title"`
	Location       string        `json:"location"`
	CWE            int           `json:"cwe"`
	Severity       string        `json:"severity"`
	AuditorVerdict string        `json:"auditor_verdict"`
	ExploitStatus  string        `json:"exploit_status"`
	FirstSeenRunID string        `json:"first_seen_run_id"`
	LastSeenRunID  string        `json:"last_seen_run_id"`
	Status         FindingStatus `json:"status"`
	ResolvedRunID  string        `json:"resolved_run_id,omitempty"`
}

// ReconcileResult summarizes the outcome of reconciling a new finding set
// against the prior persisted state.
type ReconcileResult struct {
	Inserted  []FindingRecord // brand-new findings not seen in prior state
	Updated   []FindingRecord // severity or verdict changed from prior state
	Resolved  []FindingRecord // present in prior state, absent from current run
	Unchanged []FindingRecord // identical to prior state
}
