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

// ── FindingID ─────────────────────────────────────────────────────────────────

func TestFindingID_Deterministic(t *testing.T) {
	a := rescan.FindingID(918, "Api.cs:42", "SSRF in image fetch")
	b := rescan.FindingID(918, "Api.cs:42", "SSRF in image fetch")
	if a != b {
		t.Fatalf("FindingID non-deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("expected 64-char hex digest, got %d chars", len(a))
	}
}

func TestFindingID_CaseInsensitive(t *testing.T) {
	a := rescan.FindingID(918, "API.CS:42", "SSRF In Image Fetch")
	b := rescan.FindingID(918, "api.cs:42", "ssrf in image fetch")
	if a != b {
		t.Fatalf("FindingID should normalize case: %q vs %q", a, b)
	}
}

func TestFindingID_DifferentCWEsDifferentIDs(t *testing.T) {
	a := rescan.FindingID(918, "Api.cs:42", "title")
	b := rescan.FindingID(79, "Api.cs:42", "title")
	if a == b {
		t.Fatal("different CWEs produced identical FindingIDs")
	}
}

func TestFindingID_DifferentLocationsDifferentIDs(t *testing.T) {
	a := rescan.FindingID(918, "Api.cs:42", "title")
	b := rescan.FindingID(918, "Api.cs:99", "title")
	if a == b {
		t.Fatal("different locations produced identical FindingIDs")
	}
}

// ── fileStore: FindingRecord ──────────────────────────────────────────────────

func TestFileStore_FindingRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	id := rescan.FindingID(918, "Api.cs:42", "SSRF in image fetch")
	rec := rescan.FindingRecord{
		ID:             id,
		Title:          "SSRF in image fetch",
		Location:       "Api.cs:42",
		CWE:            918,
		Severity:       "HIGH",
		AuditorVerdict: "CONFIRMED",
		ExploitStatus:  "EXPLOITED",
		FirstSeenRunID: "run-1",
		LastSeenRunID:  "run-1",
		Status:         rescan.FindingNew,
	}
	if err := s.PutFinding(ctx, rec); err != nil {
		t.Fatalf("PutFinding: %v", err)
	}
	got, err := s.GetFinding(ctx, id)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got == nil {
		t.Fatal("expected stored finding, got nil")
	}
	if got.Severity != rec.Severity || got.Status != rec.Status {
		t.Fatalf("finding mismatch: got %+v want %+v", got, rec)
	}
}

func TestFileStore_GetFindingMissingReturnsNil(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	got, err := s.GetFinding(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestFileStore_ListFindingsReturnsAll(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	for _, loc := range []string{"a.go:10", "b.go:20", "c.go:30"} {
		id := rescan.FindingID(89, loc, "SQL injection")
		if err := s.PutFinding(ctx, rescan.FindingRecord{ID: id, Location: loc, CWE: 89, Status: rescan.FindingNew}); err != nil {
			t.Fatalf("PutFinding: %v", err)
		}
	}
	all, err := s.ListFindings(ctx)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(all))
	}
}

func TestFileStore_FindingsPersistedAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	s1, _ := rescan.NewFileStore(dir)
	id := rescan.FindingID(22, "handler.go:77", "Path traversal")
	_ = s1.PutFinding(ctx, rescan.FindingRecord{
		ID:             id,
		Title:          "Path traversal",
		Location:       "handler.go:77",
		CWE:            22,
		Severity:       "HIGH",
		FirstSeenRunID: "r1",
		LastSeenRunID:  "r1",
		Status:         rescan.FindingNew,
	})
	_ = s1.Close()

	s2, _ := rescan.NewFileStore(dir)
	got, err := s2.GetFinding(ctx, id)
	if err != nil || got == nil || got.Severity != "HIGH" {
		t.Fatalf("finding did not survive reopen: got %+v, err %v", got, err)
	}
}

// ── Reconcile ─────────────────────────────────────────────────────────────────

func newFinding(cwe int, loc, title, sev, verdict, exploit string) rescan.FindingInput {
	return rescan.FindingInput{
		CWE:            cwe,
		Location:       loc,
		Title:          title,
		Severity:       sev,
		AuditorVerdict: verdict,
		ExploitStatus:  exploit,
	}
}

func TestReconcile_AllNewOnFirstRun(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	findings := []rescan.FindingInput{
		newFinding(918, "Api.cs:42", "SSRF", "HIGH", "CONFIRMED", "EXPLOITED"),
		newFinding(79, "View.cshtml:10", "XSS", "MEDIUM", "LIKELY", "INCONCLUSIVE"),
	}
	result, err := rescan.Reconcile(ctx, s, "run-1", findings)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(result.Inserted) != 2 {
		t.Fatalf("expected 2 inserted, got %d", len(result.Inserted))
	}
	if len(result.Updated)+len(result.Resolved)+len(result.Unchanged) != 0 {
		t.Fatalf("expected no updates/resolves/unchanged on first run")
	}
	for _, r := range result.Inserted {
		if r.FirstSeenRunID != "run-1" {
			t.Fatalf("expected FirstSeenRunID=run-1, got %q", r.FirstSeenRunID)
		}
	}
}

func TestReconcile_UnchangedFindingOnSecondRun(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	fi := newFinding(918, "Api.cs:42", "SSRF", "HIGH", "CONFIRMED", "EXPLOITED")
	if _, err := rescan.Reconcile(ctx, s, "run-1", []rescan.FindingInput{fi}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	result, err := rescan.Reconcile(ctx, s, "run-2", []rescan.FindingInput{fi})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(result.Unchanged) != 1 {
		t.Fatalf("expected 1 unchanged, got %d", len(result.Unchanged))
	}
	if result.Unchanged[0].FirstSeenRunID != "run-1" {
		t.Fatalf("expected FirstSeenRunID preserved as run-1")
	}
}

func TestReconcile_SeverityChangeIsUpdated(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	fi := newFinding(918, "Api.cs:42", "SSRF", "MEDIUM", "CONFIRMED", "INCONCLUSIVE")
	if _, err := rescan.Reconcile(ctx, s, "run-1", []rescan.FindingInput{fi}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	fi.Severity = "HIGH"
	fi.ExploitStatus = "EXPLOITED"
	result, err := rescan.Reconcile(ctx, s, "run-2", []rescan.FindingInput{fi})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(result.Updated) != 1 {
		t.Fatalf("expected 1 updated, got %d", len(result.Updated))
	}
	if result.Updated[0].Severity != "HIGH" {
		t.Fatalf("expected updated severity HIGH, got %q", result.Updated[0].Severity)
	}
	if result.Updated[0].FirstSeenRunID != "run-1" {
		t.Fatalf("expected FirstSeenRunID preserved as run-1")
	}
}

func TestReconcile_MissingFindingIsResolved(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	fi := newFinding(918, "Api.cs:42", "SSRF", "HIGH", "CONFIRMED", "EXPLOITED")
	if _, err := rescan.Reconcile(ctx, s, "run-1", []rescan.FindingInput{fi}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	// Second run has no findings — the prior one should be resolved.
	result, err := rescan.Reconcile(ctx, s, "run-2", nil)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(result.Resolved) != 1 {
		t.Fatalf("expected 1 resolved, got %d", len(result.Resolved))
	}
	if result.Resolved[0].ResolvedRunID != "run-2" {
		t.Fatalf("expected ResolvedRunID=run-2, got %q", result.Resolved[0].ResolvedRunID)
	}
}

func TestReconcile_AlreadyResolvedNotDoubleResolved(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	fi := newFinding(918, "Api.cs:42", "SSRF", "HIGH", "CONFIRMED", "EXPLOITED")
	// run-1: insert
	if _, err := rescan.Reconcile(ctx, s, "run-1", []rescan.FindingInput{fi}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	// run-2: resolve
	if _, err := rescan.Reconcile(ctx, s, "run-2", nil); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	// run-3: still no findings — already resolved, should not appear in Resolved again
	result, err := rescan.Reconcile(ctx, s, "run-3", nil)
	if err != nil {
		t.Fatalf("third reconcile: %v", err)
	}
	if len(result.Resolved) != 0 {
		t.Fatalf("expected already-resolved finding not to appear again, got %d resolved", len(result.Resolved))
	}
}

func TestReconcile_MixedOutcomes(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	ssrf := newFinding(918, "Api.cs:42", "SSRF", "HIGH", "CONFIRMED", "EXPLOITED")
	xss := newFinding(79, "View.cshtml:10", "XSS", "MEDIUM", "LIKELY", "INCONCLUSIVE")
	sqli := newFinding(89, "Repo.cs:5", "SQLi", "CRITICAL", "CONFIRMED", "EXPLOITED")

	// run-1: all three present
	if _, err := rescan.Reconcile(ctx, s, "run-1", []rescan.FindingInput{ssrf, xss, sqli}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	// run-2: SSRF unchanged, XSS upgraded severity, SQLi gone
	xss.Severity = "HIGH"
	result, err := rescan.Reconcile(ctx, s, "run-2", []rescan.FindingInput{ssrf, xss})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(result.Unchanged) != 1 {
		t.Fatalf("expected 1 unchanged (SSRF), got %d", len(result.Unchanged))
	}
	if len(result.Updated) != 1 {
		t.Fatalf("expected 1 updated (XSS), got %d", len(result.Updated))
	}
	if len(result.Resolved) != 1 {
		t.Fatalf("expected 1 resolved (SQLi), got %d", len(result.Resolved))
	}
	if len(result.Inserted) != 0 {
		t.Fatalf("expected 0 inserted, got %d", len(result.Inserted))
	}
}
