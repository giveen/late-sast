package rescan

import "context"

// Store persists rescan state between successive scan runs.
type Store interface {
	// GetSourceItem retrieves the previously recorded state for a repo+path pair.
	// Returns (nil, nil) when no prior record exists.
	GetSourceItem(ctx context.Context, repo, path string) (*SourceItem, error)

	// PutSourceItem stores or updates a source item.
	PutSourceItem(ctx context.Context, item SourceItem) error

	// GetTransformRecord retrieves a cached transform result by its deterministic key.
	// Returns (nil, nil) when no prior record exists.
	GetTransformRecord(ctx context.Context, key string) (*TransformRecord, error)

	// PutTransformRecord stores or updates a transform record under the given key.
	PutTransformRecord(ctx context.Context, key string, rec TransformRecord) error

	// GetFinding retrieves a persisted finding by its stable FindingID.
	// Returns (nil, nil) when no prior record exists.
	GetFinding(ctx context.Context, id string) (*FindingRecord, error)

	// PutFinding stores or updates a finding record.
	PutFinding(ctx context.Context, rec FindingRecord) error

	// ListFindings returns all persisted findings regardless of status.
	ListFindings(ctx context.Context) ([]FindingRecord, error)

	// SaveRunSummary persists the summary for a completed scan run.
	SaveRunSummary(ctx context.Context, summary RunSummary) error

	// PutLineageEdge persists a directed relationship between two findings.
	// Idempotent: calling it again with the same parent+child pair is a no-op.
	PutLineageEdge(ctx context.Context, edge LineageEdge) error

	// ListEdgesFrom returns all lineage edges whose ParentID equals parentID.
	ListEdgesFrom(ctx context.Context, parentID string) ([]LineageEdge, error)

	// ListEdgesTo returns all lineage edges whose ChildID equals childID.
	ListEdgesTo(ctx context.Context, childID string) ([]LineageEdge, error)

	// ListAllEdges returns every lineage edge in the store.
	ListAllEdges(ctx context.Context) ([]LineageEdge, error)

	// Close flushes any pending writes and releases resources held by the store.
	Close() error
}
