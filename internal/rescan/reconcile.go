package rescan

import "context"

// FindingInput is the minimal descriptor of a finding produced by the current
// scan run.  It mirrors the fields that participate in the stable identity key
// and the fields that signal a meaningful change.
type FindingInput struct {
	Title          string
	Location       string
	CWE            int
	Severity       string
	AuditorVerdict string
	ExploitStatus  string
}

// Reconcile compares a set of findings from the current scan run against the
// prior state held in the Store, persists updated records, and returns a
// ReconcileResult describing what changed.
//
// The runID should be a unique identifier for the current scan run (e.g. a
// timestamp-derived string or UUID).
//
// Algorithm:
//  1. For every input finding compute its stable FindingID.
//  2. Fetch any prior record for that ID.
//  3. If none exists → Inserted.
//  4. If it exists and severity/verdict/exploit status changed → Updated.
//  5. If it exists and nothing changed → Unchanged.
//  6. Any prior finding not present in the current input set → Resolved.
func Reconcile(ctx context.Context, store Store, runID string, current []FindingInput) (ReconcileResult, error) {
	var result ReconcileResult

	currentIDs := make(map[string]struct{}, len(current))

	for _, fi := range current {
		id := FindingID(fi.CWE, fi.Location, fi.Title)
		currentIDs[id] = struct{}{}

		prior, err := store.GetFinding(ctx, id)
		if err != nil {
			return ReconcileResult{}, err
		}

		rec := FindingRecord{
			ID:             id,
			Title:          fi.Title,
			Location:       fi.Location,
			CWE:            fi.CWE,
			Severity:       fi.Severity,
			AuditorVerdict: fi.AuditorVerdict,
			ExploitStatus:  fi.ExploitStatus,
			LastSeenRunID:  runID,
		}

		if prior == nil {
			rec.FirstSeenRunID = runID
			rec.Status = FindingNew
			result.Inserted = append(result.Inserted, rec)
		} else {
			rec.FirstSeenRunID = prior.FirstSeenRunID
			if prior.Severity != fi.Severity ||
				prior.AuditorVerdict != fi.AuditorVerdict ||
				prior.ExploitStatus != fi.ExploitStatus {
				rec.Status = FindingUpdated
				result.Updated = append(result.Updated, rec)
			} else {
				rec.Status = FindingUnchanged
				result.Unchanged = append(result.Unchanged, rec)
			}
		}

		if err := store.PutFinding(ctx, rec); err != nil {
			return ReconcileResult{}, err
		}
	}

	// Mark anything not seen in the current run as resolved.
	all, err := store.ListFindings(ctx)
	if err != nil {
		return ReconcileResult{}, err
	}
	for _, f := range all {
		if _, seen := currentIDs[f.ID]; seen {
			continue
		}
		if f.Status == FindingResolved {
			continue // already resolved in a prior run
		}
		f.Status = FindingResolved
		f.ResolvedRunID = runID
		if err := store.PutFinding(ctx, f); err != nil {
			return ReconcileResult{}, err
		}
		result.Resolved = append(result.Resolved, f)
	}

	return result, nil
}
