package orchestrator

import (
	"context"
	"encoding/json"
	"late/internal/client"
	"late/internal/common"
)

// NodeHighlightMiddleware returns a ToolMiddleware that calls onHighlight
// whenever an agent invokes read_file or search_graph. The callback receives
// the accessed file path and a bool indicating whether it is a known hotspot
// (checked against the provided hotspot set).
//
// This is used to update the "Project Map" GUI tab in real time as agents
// traverse the codebase.
func NodeHighlightMiddleware(hotspots map[string]bool, onHighlight func(filePath string, isHotspot bool)) common.ToolMiddleware {
	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			switch tc.Function.Name {
			case "read_file", "search_graph", "get_code_snippet", "trace_path":
				path := extractPathArg(tc.Function.Arguments)
				if path != "" && onHighlight != nil {
					onHighlight(path, hotspots[path])
				}
			}
			return next(ctx, tc)
		}
	}
}

// extractPathArg pulls the first string value from a set of common path
// argument names used by read_file and graph tools.
func extractPathArg(rawArgs string) string {
	var args map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return ""
	}
	for _, key := range []string{"path", "file_path", "filePath", "node_id", "query"} {
		if v, ok := args[key]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil && s != "" {
				return s
			}
		}
	}
	return ""
}
