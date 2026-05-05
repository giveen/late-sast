package rescan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"late/internal/rescan"
)

// ── hash ──────────────────────────────────────────────────────────────────────

func TestHashBytes_Deterministic(t *testing.T) {
	a := rescan.HashBytes([]byte("hello"))
	b := rescan.HashBytes([]byte("hello"))
	if a != b {
		t.Fatalf("HashBytes non-deterministic: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("expected 64-char hex digest, got %d chars", len(a))
	}
}

func TestHashBytes_DistinctInputsDistinctHashes(t *testing.T) {
	if rescan.HashBytes([]byte("a")) == rescan.HashBytes([]byte("b")) {
		t.Fatal("distinct inputs produced identical hashes")
	}
}

func TestHashFile_MatchesHashBytes(t *testing.T) {
	content := []byte("file content for hashing")
	path := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	got, err := rescan.HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	want := rescan.HashBytes(content)
	if got != want {
		t.Fatalf("HashFile %q != HashBytes %q", got, want)
	}
}

func TestHashFile_MissingFileErrors(t *testing.T) {
	_, err := rescan.HashFile(filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestTransformKey_Deterministic(t *testing.T) {
	k1 := rescan.TransformKey("semgrep", "v1", "abc123")
	k2 := rescan.TransformKey("semgrep", "v1", "abc123")
	if k1 != k2 {
		t.Fatalf("TransformKey non-deterministic")
	}
}

func TestTransformKey_DifferentInputsDifferentKeys(t *testing.T) {
	k1 := rescan.TransformKey("semgrep", "v1", "abc123")
	k2 := rescan.TransformKey("semgrep", "v1", "def456")
	if k1 == k2 {
		t.Fatal("different inputs produced identical transform keys")
	}
}

func TestTransformKey_DifferentTransformsDifferentKeys(t *testing.T) {
	k1 := rescan.TransformKey("semgrep", "v1", "abc")
	k2 := rescan.TransformKey("trivy", "v1", "abc")
	if k1 == k2 {
		t.Fatal("different transform names produced identical transform keys")
	}
}

// ── fileStore: SourceItem ─────────────────────────────────────────────────────

func newStore(t *testing.T) rescan.Store {
	t.Helper()
	s, err := rescan.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func TestFileStore_SourceItemRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	item := rescan.SourceItem{
		Repo:        "github.com/example/app",
		Path:        "pkg/api/handler.go",
		ContentHash: "deadbeef",
		Commit:      "abc123",
		LastSeenAt:  time.Now().Truncate(time.Second),
	}
	if err := s.PutSourceItem(ctx, item); err != nil {
		t.Fatalf("PutSourceItem: %v", err)
	}
	got, err := s.GetSourceItem(ctx, item.Repo, item.Path)
	if err != nil {
		t.Fatalf("GetSourceItem: %v", err)
	}
	if got == nil {
		t.Fatal("expected stored item, got nil")
	}
	if got.ContentHash != item.ContentHash || got.Commit != item.Commit {
		t.Fatalf("stored item mismatch: got %+v want %+v", got, item)
	}
}

func TestFileStore_GetSourceItemMissingReturnsNil(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	got, err := s.GetSourceItem(ctx, "repo", "nonexistent.go")
	if err != nil {
		t.Fatalf("GetSourceItem: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing item, got %+v", got)
	}
}

// ── fileStore: TransformRecord ────────────────────────────────────────────────

func TestFileStore_TransformRecordRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	key := rescan.TransformKey("semgrep", "v1", "inputhash")
	rec := rescan.TransformRecord{
		RunID:                "run-1",
		TransformName:        "semgrep",
		TransformVersionHash: "v1",
		InputHash:            "inputhash",
		OutputHash:           "outputhash",
		Status:               "ok",
		DurationMS:           1234,
		CreatedAt:            time.Now().Truncate(time.Second),
	}
	if err := s.PutTransformRecord(ctx, key, rec); err != nil {
		t.Fatalf("PutTransformRecord: %v", err)
	}
	got, err := s.GetTransformRecord(ctx, key)
	if err != nil {
		t.Fatalf("GetTransformRecord: %v", err)
	}
	if got == nil {
		t.Fatal("expected stored record, got nil")
	}
	if got.Status != rec.Status || got.OutputHash != rec.OutputHash {
		t.Fatalf("stored record mismatch: got %+v want %+v", got, rec)
	}
}

func TestFileStore_GetTransformRecordMissingReturnsNil(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	got, err := s.GetTransformRecord(ctx, "nonexistent-key")
	if err != nil {
		t.Fatalf("GetTransformRecord: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing record, got %+v", got)
	}
}

// ── fileStore: persistence across reopen ─────────────────────────────────────

func TestFileStore_PersistedAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Write with first store instance.
	s1, err := rescan.NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore (first): %v", err)
	}
	item := rescan.SourceItem{Repo: "repo", Path: "main.go", ContentHash: "hash1"}
	if err := s1.PutSourceItem(ctx, item); err != nil {
		t.Fatalf("PutSourceItem: %v", err)
	}
	key := rescan.TransformKey("trivy", "v2", "hash1")
	rec := rescan.TransformRecord{RunID: "r1", Status: "ok", OutputHash: "out1"}
	if err := s1.PutTransformRecord(ctx, key, rec); err != nil {
		t.Fatalf("PutTransformRecord: %v", err)
	}
	_ = s1.Close()

	// Reopen and verify data survived.
	s2, err := rescan.NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore (second): %v", err)
	}
	gotItem, err := s2.GetSourceItem(ctx, item.Repo, item.Path)
	if err != nil || gotItem == nil || gotItem.ContentHash != item.ContentHash {
		t.Fatalf("source item did not survive reopen: got %+v, err %v", gotItem, err)
	}
	gotRec, err := s2.GetTransformRecord(ctx, key)
	if err != nil || gotRec == nil || gotRec.OutputHash != rec.OutputHash {
		t.Fatalf("transform record did not survive reopen: got %+v, err %v", gotRec, err)
	}
}

// ── scope ─────────────────────────────────────────────────────────────────────

func TestComputeDeltaScope_EmptyStore_AllSourcesAreChanged(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	current := []rescan.SourceItem{
		{Repo: "r", Path: "a.go", ContentHash: "h1"},
		{Repo: "r", Path: "b.go", ContentHash: "h2"},
	}
	scope, err := rescan.ComputeDeltaScope(ctx, s, current)
	if err != nil {
		t.Fatalf("ComputeDeltaScope: %v", err)
	}
	if len(scope.ChangedSources) != 2 {
		t.Fatalf("expected 2 changed sources, got %d", len(scope.ChangedSources))
	}
}

func TestComputeDeltaScope_UnchangedItemsExcluded(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Pre-populate store with existing state.
	_ = s.PutSourceItem(ctx, rescan.SourceItem{Repo: "r", Path: "a.go", ContentHash: "h1"})
	_ = s.PutSourceItem(ctx, rescan.SourceItem{Repo: "r", Path: "b.go", ContentHash: "h2"})

	// Current scan sees same hashes → nothing changed.
	current := []rescan.SourceItem{
		{Repo: "r", Path: "a.go", ContentHash: "h1"},
		{Repo: "r", Path: "b.go", ContentHash: "h2"},
	}
	scope, err := rescan.ComputeDeltaScope(ctx, s, current)
	if err != nil {
		t.Fatalf("ComputeDeltaScope: %v", err)
	}
	if len(scope.ChangedSources) != 0 {
		t.Fatalf("expected 0 changed sources, got %d: %v", len(scope.ChangedSources), scope.ChangedSources)
	}
}

func TestComputeDeltaScope_ChangedHashDetected(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	_ = s.PutSourceItem(ctx, rescan.SourceItem{Repo: "r", Path: "a.go", ContentHash: "old-hash"})
	_ = s.PutSourceItem(ctx, rescan.SourceItem{Repo: "r", Path: "b.go", ContentHash: "h2"})

	// a.go changed; b.go is unchanged.
	current := []rescan.SourceItem{
		{Repo: "r", Path: "a.go", ContentHash: "new-hash"},
		{Repo: "r", Path: "b.go", ContentHash: "h2"},
	}
	scope, err := rescan.ComputeDeltaScope(ctx, s, current)
	if err != nil {
		t.Fatalf("ComputeDeltaScope: %v", err)
	}
	if len(scope.ChangedSources) != 1 {
		t.Fatalf("expected 1 changed source, got %d: %v", len(scope.ChangedSources), scope.ChangedSources)
	}
	if scope.ChangedSources[0].Path != "a.go" {
		t.Fatalf("expected a.go as changed, got %q", scope.ChangedSources[0].Path)
	}
}

func TestComputeDeltaScope_NewFileIsChanged(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Store only knows about a.go; b.go is new.
	_ = s.PutSourceItem(ctx, rescan.SourceItem{Repo: "r", Path: "a.go", ContentHash: "h1"})

	current := []rescan.SourceItem{
		{Repo: "r", Path: "a.go", ContentHash: "h1"},
		{Repo: "r", Path: "b.go", ContentHash: "h2"},
	}
	scope, err := rescan.ComputeDeltaScope(ctx, s, current)
	if err != nil {
		t.Fatalf("ComputeDeltaScope: %v", err)
	}
	if len(scope.ChangedSources) != 1 {
		t.Fatalf("expected 1 changed source (new file), got %d", len(scope.ChangedSources))
	}
	if scope.ChangedSources[0].Path != "b.go" {
		t.Fatalf("expected b.go as new file, got %q", scope.ChangedSources[0].Path)
	}
}
