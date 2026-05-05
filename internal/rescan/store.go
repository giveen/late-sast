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

	// SaveRunSummary persists the summary for a completed scan run.
	SaveRunSummary(ctx context.Context, summary RunSummary) error

	// Close flushes any pending writes and releases resources held by the store.
	Close() error
}
