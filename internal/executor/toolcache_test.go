package executor

import "testing"

func TestToolResultCacheInvalidateAll(t *testing.T) {
	cache := NewToolResultCache()
	cache.Set("read_file", `{"path":"a.go"}`, "contents")

	if _, ok := cache.Get("read_file", `{"path":"a.go"}`); !ok {
		t.Fatal("expected cache entry to exist before invalidation")
	}

	cache.InvalidateAll()

	if _, ok := cache.Get("read_file", `{"path":"a.go"}`); ok {
		t.Fatal("expected cache entry to be removed after invalidation")
	}
}

func TestMutatesWorkspace(t *testing.T) {
	for _, toolName := range []string{"write_file", "compose_patch", "implementations", "bash"} {
		if !mutatesWorkspace(toolName) {
			t.Fatalf("expected %q to be treated as workspace-mutating", toolName)
		}
	}
	if mutatesWorkspace("read_file") {
		t.Fatal("did not expect read_file to be treated as workspace-mutating")
	}
}
