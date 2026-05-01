package debug

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger provides structured debug logging to a file.
type Logger struct {
	mu       sync.Mutex
	filepath string
	enabled  bool
}

// New creates a new debug logger. If outputDir is empty, logging is disabled.
func New(outputDir string) *Logger {
	l := &Logger{
		enabled: outputDir != "",
	}
	if l.enabled {
		// Generate debug log filename with timestamp
		timestamp := time.Now().Format("20060102_150405")
		l.filepath = filepath.Join(outputDir, fmt.Sprintf("debug_%s.log", timestamp))
	}
	return l
}

// Enabled returns whether debug logging is active.
func (l *Logger) Enabled() bool {
	return l.enabled
}

// FilePath returns the path of the log file being written.
func (l *Logger) FilePath() string {
	return l.filepath
}

// LogLLMRequest logs an outgoing LLM request.
func (l *Logger) LogLLMRequest(method, url string, headers map[string]string, body interface{}) {
	if !l.enabled {
		return
	}
	l.logEntry("LLM_REQUEST", map[string]interface{}{
		"method":  method,
		"url":     url,
		"headers": redactHeaders(headers),
		"body":    body,
	})
}

// LogLLMResponse logs an incoming LLM response.
func (l *Logger) LogLLMResponse(statusCode int, body interface{}, latencyMs int64) {
	if !l.enabled {
		return
	}
	l.logEntry("LLM_RESPONSE", map[string]interface{}{
		"status_code": statusCode,
		"latency_ms":  latencyMs,
		"body":        body,
	})
}

// LogToolCall logs a tool invocation.
func (l *Logger) LogToolCall(toolName string, arguments json.RawMessage) {
	if !l.enabled {
		return
	}
	var parsed interface{}
	if err := json.Unmarshal(arguments, &parsed); err != nil {
		parsed = string(arguments)
	}
	l.logEntry("TOOL_CALL", map[string]interface{}{
		"tool":      toolName,
		"arguments": parsed,
	})
}

// LogToolResult logs a tool execution result.
func (l *Logger) LogToolResult(toolName, toolCallID, result string) {
	if !l.enabled {
		return
	}
	l.logEntry("TOOL_RESULT", map[string]interface{}{
		"tool":         toolName,
		"tool_call_id": toolCallID,
		"result":       result,
	})
}

// LogError logs an error event.
func (l *Logger) LogError(message string, err error, context map[string]interface{}) {
	if !l.enabled {
		return
	}
	if context == nil {
		context = make(map[string]interface{})
	}
	context["error"] = err.Error()
	l.logEntry("ERROR", map[string]interface{}{
		"message": message,
		"context": context,
	})
}

// LogEvent logs a generic event.
func (l *Logger) LogEvent(eventType, message string, context map[string]interface{}) {
	if !l.enabled {
		return
	}
	entry := map[string]interface{}{
		"message": message,
	}
	if context != nil {
		entry["context"] = context
	}
	l.logEntry(eventType, entry)
}

// logEntry writes a structured log entry to file.
func (l *Logger) logEntry(eventType string, data map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	logEntry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339Nano),
		"event":     eventType,
		"data":      data,
	}

	jsonData, err := json.MarshalIndent(logEntry, "", "  ")
	if err != nil {
		return
	}

	f, err := os.OpenFile(l.filepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "%s\n", string(jsonData))
}

// redactHeaders returns a copy of headers with sensitive values masked.
func redactHeaders(headers map[string]string) map[string]string {
	redacted := make(map[string]string)
	sensitiveKeys := map[string]bool{
		"Authorization": true,
		"X-API-Key":     true,
		"Cookie":        true,
	}
	for k, v := range headers {
		if sensitiveKeys[k] {
			redacted[k] = "[REDACTED]"
		} else {
			redacted[k] = v
		}
	}
	return redacted
}
