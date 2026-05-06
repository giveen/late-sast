package rescan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// fileStore is a simple JSON-on-disk implementation of Store.
// State is loaded once on open and written atomically after every mutation.
// It is safe for concurrent use within a single process.
type fileStore struct {
	mu       sync.Mutex
	dir      string
	sources  map[string]SourceItem      // key: sourceKey(repo, path)
	records  map[string]TransformRecord // key: transform key
	findings map[string]FindingRecord   // key: FindingID
}

// storeState is the on-disk JSON envelope.
type storeState struct {
	Sources  map[string]SourceItem      `json:"sources"`
	Records  map[string]TransformRecord `json:"records"`
	Findings map[string]FindingRecord   `json:"findings"`
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
	return s.save()
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
	return s.save()
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
	return s.save()
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

func (s *fileStore) SaveRunSummary(_ context.Context, summary RunSummary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	// Not covered by the main mutex; summaries are append-only and written once per run.
	return atomicWrite(filepath.Join(s.dir, "run_summary.json"), data)
}

func (s *fileStore) Close() error { return nil }

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
	return nil
}

// save writes current state to disk atomically. Must be called under s.mu.
func (s *fileStore) save() error {
	data, err := json.Marshal(storeState{
		Sources:  s.sources,
		Records:  s.records,
		Findings: s.findings,
	})
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, "state.json"), data)
}

// atomicWrite writes data to path via a sibling temp file + rename so that
// readers never see a partial write.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
