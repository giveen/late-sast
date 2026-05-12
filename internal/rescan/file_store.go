package rescan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// fileStore is a simple JSON-on-disk implementation of Store.
// Mutations are accumulated in memory and flushed atomically on Close (or via
// an explicit flush). It is safe for concurrent use within a single process.
type fileStore struct {
	mu       sync.Mutex
	dir      string
	dirty    bool
	sources  map[string]SourceItem      // key: sourceKey(repo, path)
	records  map[string]TransformRecord // key: transform key
	findings map[string]FindingRecord   // key: FindingID
	edges    map[string]LineageEdge     // key: edgeKey(parentID, childID)
}

// storeState is the on-disk JSON envelope.
type storeState struct {
	Sources  map[string]SourceItem      `json:"sources"`
	Records  map[string]TransformRecord `json:"records"`
	Findings map[string]FindingRecord   `json:"findings"`
	Edges    map[string]LineageEdge     `json:"edges,omitempty"`
}

// NewFileStore opens (or creates) a file-based Store rooted at dir.
// If no prior state file is found the store starts empty, which is correct
// for the first scan run against a target.
func NewFileStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	s := &fileStore{
		dir:      dir,
		sources:  make(map[string]SourceItem),
		records:  make(map[string]TransformRecord),
		findings: make(map[string]FindingRecord),
		edges:    make(map[string]LineageEdge),
	}
	_ = s.load() // ignore "file not found" on first run
	return s, nil
}

func sourceKey(repo, path string) string { return repo + "\x00" + path }

func (s *fileStore) GetSourceItem(_ context.Context, repo, path string) (*SourceItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item, ok := s.sources[sourceKey(repo, path)]; ok {
		cp := item
		return &cp, nil
	}
	return nil, nil
}

func (s *fileStore) PutSourceItem(_ context.Context, item SourceItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources[sourceKey(item.Repo, item.Path)] = item
	s.dirty = true
	return nil
}

func (s *fileStore) GetTransformRecord(_ context.Context, key string) (*TransformRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.records[key]; ok {
		cp := rec
		return &cp, nil
	}
	return nil, nil
}

func (s *fileStore) PutTransformRecord(_ context.Context, key string, rec TransformRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key] = rec
	s.dirty = true
	return nil
}

func (s *fileStore) GetFinding(_ context.Context, id string) (*FindingRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.findings[id]; ok {
		cp := rec
		return &cp, nil
	}
	return nil, nil
}

func (s *fileStore) PutFinding(_ context.Context, rec FindingRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings[rec.ID] = rec
	s.dirty = true
	return nil
}

func (s *fileStore) ListFindings(_ context.Context) ([]FindingRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FindingRecord, 0, len(s.findings))
	for _, f := range s.findings {
		out = append(out, f)
	}
	return out, nil
}

func (s *fileStore) PutLineageEdge(ctx context.Context, edge LineageEdge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := putLineageEdgeCtx(ctx, s.edges, edge); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

func (s *fileStore) ListEdgesFrom(ctx context.Context, parentID string) ([]LineageEdge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listEdgesFromCtx(ctx, s.edges, parentID)
}

func (s *fileStore) ListEdgesTo(ctx context.Context, childID string) ([]LineageEdge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listEdgesToCtx(ctx, s.edges, childID)
}

func (s *fileStore) ListAllEdges(ctx context.Context) ([]LineageEdge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listAllEdgesCtx(ctx, s.edges)
}

func (s *fileStore) SaveRunSummary(_ context.Context, summary RunSummary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	// Not covered by the main mutex; summaries are append-only and written once per run.
	return atomicWrite(filepath.Join(s.dir, "run_summary.json"), data)
}

func (s *fileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	err := s.save()
	if err == nil {
		s.dirty = false
	}
	return err
}

// load reads persisted state from disk. Must NOT be called under s.mu.
func (s *fileStore) load() error {
	data, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if err != nil {
		return err
	}
	var st storeState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.Sources != nil {
		s.sources = st.Sources
	}
	if st.Records != nil {
		s.records = st.Records
	}
	if st.Findings != nil {
		s.findings = st.Findings
	}
	if st.Edges != nil {
		s.edges = st.Edges
	}
	return nil
}

// save writes current state to disk atomically. Must be called under s.mu.
func (s *fileStore) save() error {
	data, err := json.Marshal(storeState{
		Sources:  s.sources,
		Records:  s.records,
		Findings: s.findings,
		Edges:    s.edges,
	})
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, "state.json"), data)
}

// atomicWrite writes data to path via a sibling temp file + rename so that
// readers never see a partial write. Uses os.CreateTemp to avoid races between
// concurrent writers that would otherwise collide on a fixed ".tmp" path.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
