package rescan

import "context"

// ComputeDeltaScope determines which of the supplied current SourceItems have
// changed (or are entirely new) relative to what the store last recorded.
//
// An item is considered changed when its ContentHash differs from the stored
// record, or when no prior record exists.  Items whose hash is identical to the
// stored record are omitted from the returned scope, allowing downstream
// transforms to be skipped.
func ComputeDeltaScope(ctx context.Context, store Store, current []SourceItem) (DeltaScope, error) {
	var changed []SourceItem
	for _, item := range current {
		prev, err := store.GetSourceItem(ctx, item.Repo, item.Path)
		if err != nil {
			return DeltaScope{}, err
		}
		if prev == nil || prev.ContentHash != item.ContentHash {
			changed = append(changed, item)
		}
	}
	return DeltaScope{ChangedSources: changed}, nil
}
