package rescan

import (
	"context"
	"strings"
)

// LineageEdgeKind describes how two findings are related across runs.
type LineageEdgeKind string

const (
	// EdgeConfirmed means the child finding is a confirmed exploitation of the parent.
	EdgeConfirmed LineageEdgeKind = "confirmed"
	// EdgeEscalated means the child finding reflects a privilege escalation from the parent.
	EdgeEscalated LineageEdgeKind = "escalated"
	// EdgeChained means the child was reached by chaining from the parent.
	EdgeChained LineageEdgeKind = "chained"
)

// LineageEdge records a directed relationship between two findings.
// ParentID and ChildID are stable FindingIDs (from FindingID()).
type LineageEdge struct {
	ParentID string          `json:"parent_id"`
	ChildID  string          `json:"child_id"`
	Kind     LineageEdgeKind `json:"kind"`
	RunID    string          `json:"run_id"` // run in which the edge was first recorded
}

// edgeKey returns a storage key for an edge that is stable under round-trip.
func edgeKey(parentID, childID string) string { return parentID + "\x00" + childID }

// RetestScope determines which findings require retesting in the next run.
//
// A finding is included when any of the following is true:
//  1. Its source file appears in delta.ChangedSources (the underlying code changed).
//  2. Its ExploitStatus is not "confirmed" — i.e. exploitation has not yet been
//     verified and may succeed on a fresh attempt.
//  3. Its Status is FindingNew or FindingUpdated in the current run.
//  4. Any finding reachable from it via lineage edges also satisfies the above.
//
// The caller provides the full current finding slice and the DeltaScope produced
// by ComputeDeltaScope so that this function can be used without touching the store.
func RetestScope(findings []FindingRecord, delta DeltaScope, edges []LineageEdge) []FindingRecord {
	// Build a set of changed source paths for O(1) lookup.
	changedPaths := make(map[string]struct{}, len(delta.ChangedSources))
	for _, src := range delta.ChangedSources {
		changedPaths[src.Path] = struct{}{}
	}

	// Build a child→parent and parent→child index so we can propagate retest status.
	childrenOf := make(map[string][]string) // parent → []child
	for _, e := range edges {
		childrenOf[e.ParentID] = append(childrenOf[e.ParentID], e.ChildID)
	}

	// First pass: mark directly eligible findings.
	needsRetest := make(map[string]bool, len(findings))
	for _, f := range findings {
		if directlyNeedsRetest(f, changedPaths) {
			needsRetest[f.ID] = true
		}
	}

	// Second pass: propagate forward along lineage edges (parent needs retest →
	// child needs retest, because parent may open new exploit paths for child).
	changed := true
	for changed {
		changed = false
		for parentID, children := range childrenOf {
			if !needsRetest[parentID] {
				continue
			}
			for _, childID := range children {
				if !needsRetest[childID] {
					needsRetest[childID] = true
					changed = true
				}
			}
		}
	}

	// Collect results preserving input order.
	var out []FindingRecord
	for _, f := range findings {
		if needsRetest[f.ID] {
			out = append(out, f)
		}
	}
	return out
}

// directlyNeedsRetest returns true when a finding is directly eligible for retest
// without considering lineage propagation.
func directlyNeedsRetest(f FindingRecord, changedPaths map[string]struct{}) bool {
	// Source code changed for this finding's location.
	loc := f.Location
	if idx := strings.Index(loc, ":"); idx != -1 {
		loc = loc[:idx] // strip line numbers like "src/foo.go:42"
	}
	if _, changed := changedPaths[loc]; changed {
		return true
	}
	// Exploit has not yet been confirmed.
	if f.ExploitStatus != "confirmed" {
		return true
	}
	// Finding is new or updated in this run.
	if f.Status == FindingNew || f.Status == FindingUpdated {
		return true
	}
	return false
}

// ── Store extension ──────────────────────────────────────────────────────────

// PutLineageEdge persists a directed lineage edge between two findings.
// Calling it again with the same parent+child pair is a no-op (idempotent).
func putLineageEdge(edges map[string]LineageEdge, edge LineageEdge) {
	k := edgeKey(edge.ParentID, edge.ChildID)
	if _, exists := edges[k]; !exists {
		edges[k] = edge
	}
}

// listEdgesFrom returns all edges whose ParentID equals parentID.
func listEdgesFrom(edges map[string]LineageEdge, parentID string) []LineageEdge {
	var out []LineageEdge
	for _, e := range edges {
		if e.ParentID == parentID {
			out = append(out, e)
		}
	}
	return out
}

// listEdgesTo returns all edges whose ChildID equals childID.
func listEdgesTo(edges map[string]LineageEdge, childID string) []LineageEdge {
	var out []LineageEdge
	for _, e := range edges {
		if e.ChildID == childID {
			out = append(out, e)
		}
	}
	return out
}

// These are the context-accepting wrappers that satisfy the Store interface extension.
// They are called by fileStore methods defined in file_store.go.

func putLineageEdgeCtx(_ context.Context, edges map[string]LineageEdge, edge LineageEdge) error {
	putLineageEdge(edges, edge)
	return nil
}

func listEdgesFromCtx(_ context.Context, edges map[string]LineageEdge, parentID string) ([]LineageEdge, error) {
	return listEdgesFrom(edges, parentID), nil
}

func listEdgesToCtx(_ context.Context, edges map[string]LineageEdge, childID string) ([]LineageEdge, error) {
	return listEdgesTo(edges, childID), nil
}

func listAllEdgesCtx(_ context.Context, edges map[string]LineageEdge) ([]LineageEdge, error) {
	out := make([]LineageEdge, 0, len(edges))
	for _, e := range edges {
		out = append(out, e)
	}
	return out, nil
}
