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

// ── LineageEdge / fileStore ────────────────────────────────────────────────────

func TestFileStore_LineageEdgeRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	parentID := rescan.FindingID(918, "Api.cs:42", "SSRF")
	childID := rescan.FindingID(284, "Api.cs:42", "Privilege escalation via SSRF")

	edge := rescan.LineageEdge{
		ParentID: parentID,
		ChildID:  childID,
		Kind:     rescan.EdgeEscalated,
		RunID:    "run-2",
	}
	if err := s.PutLineageEdge(ctx, edge); err != nil {
		t.Fatalf("PutLineageEdge: %v", err)
	}
	from, err := s.ListEdgesFrom(ctx, parentID)
	if err != nil {
		t.Fatalf("ListEdgesFrom: %v", err)
	}
	if len(from) != 1 || from[0].ChildID != childID {
		t.Fatalf("expected 1 edge from parent, got %+v", from)
	}
	to, err := s.ListEdgesTo(ctx, childID)
	if err != nil {
		t.Fatalf("ListEdgesTo: %v", err)
	}
	if len(to) != 1 || to[0].ParentID != parentID {
		t.Fatalf("expected 1 edge to child, got %+v", to)
	}
}

func TestFileStore_LineageEdgeIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	parentID := rescan.FindingID(79, "x.go:1", "XSS")
	childID := rescan.FindingID(352, "x.go:1", "CSRF")
	edge := rescan.LineageEdge{ParentID: parentID, ChildID: childID, Kind: rescan.EdgeChained, RunID: "run-1"}

	// Inserting the same edge twice should not duplicate it.
	_ = s.PutLineageEdge(ctx, edge)
	_ = s.PutLineageEdge(ctx, edge)

	all, err := s.ListAllEdges(ctx)
	if err != nil {
		t.Fatalf("ListAllEdges: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 edge after duplicate insert, got %d", len(all))
	}
}

func TestFileStore_LineageEdgesPersistedAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	s1, _ := rescan.NewFileStore(dir)
	parentID := rescan.FindingID(918, "api.go:10", "SSRF")
	childID := rescan.FindingID(502, "api.go:10", "Deserialization")
	edge := rescan.LineageEdge{ParentID: parentID, ChildID: childID, Kind: rescan.EdgeConfirmed, RunID: "r1"}
	_ = s1.PutLineageEdge(ctx, edge)
	_ = s1.Close()

	s2, _ := rescan.NewFileStore(dir)
	all, err := s2.ListAllEdges(ctx)
	if err != nil {
		t.Fatalf("ListAllEdges after reopen: %v", err)
	}
	if len(all) != 1 || all[0].Kind != rescan.EdgeConfirmed {
		t.Fatalf("edge did not survive reopen: got %+v", all)
	}
}

func TestFileStore_ListEdgesFrom_EmptyWhenNone(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	edges, err := s.ListEdgesFrom(ctx, "no-such-id")
	if err != nil {
		t.Fatalf("ListEdgesFrom: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("expected empty, got %+v", edges)
	}
}

// ── RetestScope ────────────────────────────────────────────────────────────────

func makeRecord(id string, status rescan.FindingStatus, exploitStatus, loc string) rescan.FindingRecord {
	return rescan.FindingRecord{
		ID:            id,
		Location:      loc,
		ExploitStatus: exploitStatus,
		Status:        status,
	}
}

func TestRetestScope_ChangedSourceTriggersRetest(t *testing.T) {
	id := rescan.FindingID(89, "repo.go:5", "SQLi")
	findings := []rescan.FindingRecord{makeRecord(id, rescan.FindingUnchanged, "confirmed", "repo.go:5")}
	delta := rescan.DeltaScope{ChangedSources: []rescan.SourceItem{{Path: "repo.go"}}}

	scope := rescan.RetestScope(findings, delta, nil)
	if len(scope) != 1 {
		t.Fatalf("expected 1 finding to retest (source changed), got %d", len(scope))
	}
}

func TestRetestScope_UnconfirmedExploitTriggersRetest(t *testing.T) {
	id := rescan.FindingID(79, "view.go:20", "XSS")
	findings := []rescan.FindingRecord{makeRecord(id, rescan.FindingUnchanged, "inconclusive", "view.go:20")}
	delta := rescan.DeltaScope{} // no source changes

	scope := rescan.RetestScope(findings, delta, nil)
	if len(scope) != 1 {
		t.Fatalf("expected 1 finding to retest (unconfirmed exploit), got %d", len(scope))
	}
}

func TestRetestScope_ConfirmedUnchangedSourceSkipped(t *testing.T) {
	id := rescan.FindingID(918, "api.go:42", "SSRF")
	// Confirmed + unchanged + source not changed → should NOT be retested.
	findings := []rescan.FindingRecord{makeRecord(id, rescan.FindingUnchanged, "confirmed", "api.go:42")}
	delta := rescan.DeltaScope{ChangedSources: []rescan.SourceItem{{Path: "other.go"}}}

	scope := rescan.RetestScope(findings, delta, nil)
	if len(scope) != 0 {
		t.Fatalf("expected 0 findings to retest (confirmed + source unchanged), got %d", len(scope))
	}
}

func TestRetestScope_NewFindingAlwaysRetested(t *testing.T) {
	id := rescan.FindingID(22, "upload.go:7", "Path traversal")
	findings := []rescan.FindingRecord{makeRecord(id, rescan.FindingNew, "confirmed", "upload.go:7")}
	delta := rescan.DeltaScope{}

	scope := rescan.RetestScope(findings, delta, nil)
	if len(scope) != 1 {
		t.Fatalf("expected 1 finding (new status always retested), got %d", len(scope))
	}
}

func TestRetestScope_LineagePropagation(t *testing.T) {
	// Parent: confirmed + unchanged source → would normally be skipped.
	// Child: same. But if parent needs retest due to lineage propagation from
	// a grandparent that does need retest, child also gets pulled in.
	grandparentID := rescan.FindingID(918, "api.go:1", "SSRF")
	parentID := rescan.FindingID(284, "api.go:1", "Privesc")
	childID := rescan.FindingID(502, "api.go:1", "Deser")

	grandparent := makeRecord(grandparentID, rescan.FindingUnchanged, "inconclusive", "api.go:1")
	parent := makeRecord(parentID, rescan.FindingUnchanged, "confirmed", "other.go:1")
	child := makeRecord(childID, rescan.FindingUnchanged, "confirmed", "other.go:1")

	edges := []rescan.LineageEdge{
		{ParentID: grandparentID, ChildID: parentID, Kind: rescan.EdgeEscalated},
		{ParentID: parentID, ChildID: childID, Kind: rescan.EdgeChained},
	}
	delta := rescan.DeltaScope{}

	scope := rescan.RetestScope([]rescan.FindingRecord{grandparent, parent, child}, delta, edges)
	if len(scope) != 3 {
		t.Fatalf("expected all 3 findings via lineage propagation, got %d", len(scope))
	}
}

func TestRetestScope_LineageDoesNotPropagateFromSkipped(t *testing.T) {
	// Parent: confirmed + unchanged → skipped.
	// Child: also confirmed + unchanged.
	// Edge from parent → child. Neither needs retest.
	parentID := rescan.FindingID(918, "api.go:1", "SSRF")
	childID := rescan.FindingID(284, "api.go:2", "Privesc")

	parent := makeRecord(parentID, rescan.FindingUnchanged, "confirmed", "api.go:1")
	child := makeRecord(childID, rescan.FindingUnchanged, "confirmed", "api.go:2")

	edges := []rescan.LineageEdge{{ParentID: parentID, ChildID: childID, Kind: rescan.EdgeChained}}
	delta := rescan.DeltaScope{ChangedSources: []rescan.SourceItem{{Path: "unrelated.go"}}}

	scope := rescan.RetestScope([]rescan.FindingRecord{parent, child}, delta, edges)
	if len(scope) != 0 {
		t.Fatalf("expected 0 findings (no retest triggers), got %d: %+v", len(scope), scope)
	}
}
