package tool

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"late/internal/common"
)

// getToolParamReCache caches compiled regexes for GetToolParam's streaming
// fallback path, keyed by the parameter name. Each unique key is compiled once.
var getToolParamReCache sync.Map // string → *regexp.Regexp

func getToolParamRe(key string) *regexp.Regexp {
	if v, ok := getToolParamReCache.Load(key); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*"([^"]*)`, regexp.QuoteMeta(key)))
	getToolParamReCache.Store(key, re)
	return re
}

// GetToolParam extracts a string parameter from tool arguments
func GetToolParam(args json.RawMessage, key string) string {
	var params map[string]any
	if err := json.Unmarshal(args, &params); err != nil {
		// Fallback for partial JSON during streaming where the unmarshal fails
		re := getToolParamRe(key)
		matches := re.FindStringSubmatch(string(args))
		if len(matches) > 1 {
			return matches[1]
		}
		return ""
	}
	val, ok := params[key].(string)
	if !ok {
		return ""
	}
	return val
}

// Truncate shortens a string to maxLen characters, adding "..." if truncated
func Truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// detectLineEnding returns the dominant line ending of the content.
// If it's consistently CRLF, it returns "\r\n".
// Otherwise (if consistent LF or mixed), it returns "\n".
func detectLineEnding(content string) string {
	crlfCount := strings.Count(content, "\r\n")
	lfCount := strings.Count(content, "\n")

	if crlfCount > 0 && crlfCount == lfCount {
		return "\r\n"
	}
	// Defaults to Unix for LF-only, mixed, or empty content.
	return "\n"
}

// normalizeToUnix converts all CRLF to LF.
func normalizeToUnix(content string) string {
	return strings.ReplaceAll(content, "\r\n", "\n")
}

// restoreLineEnding converts all LF to the specified lineEnding (e.g., "\r\n").
// If lineEnding is "\n", it does nothing.
func restoreLineEnding(content, lineEnding string) string {
	if lineEnding == "\r\n" {
		return strings.ReplaceAll(content, "\n", "\r\n")
	}
	return content
}

// IsBinary detects if the given data is likely binary.
// It checks for the presence of null bytes in the first 8KB of data.
func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Check first 8KB for null bytes
	limit := len(data)
	if limit > 8192 {
		limit = 8192
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// ParseArchitectureData unmarshals JSON architecture data from get_architecture MCP tool.
func ParseArchitectureData(jsonStr string) (common.ArchitectureData, error) {
	var data common.ArchitectureData
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return common.ArchitectureData{}, fmt.Errorf("invalid architecture JSON: %w", err)
	}
	return data, nil
}
