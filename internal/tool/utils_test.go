package tool

import (
	"encoding/json"
	"testing"
)

func TestGetToolParam_basic(t *testing.T) {
	args := json.RawMessage(`{"container_name":"my-container","path":"/app"}`)
	if got := GetToolParam(args, "container_name"); got != "my-container" {
		t.Errorf("GetToolParam(container_name) = %q, want my-container", got)
	}
	if got := GetToolParam(args, "path"); got != "/app" {
		t.Errorf("GetToolParam(path) = %q, want /app", got)
	}
}

func TestGetToolParam_missing(t *testing.T) {
	args := json.RawMessage(`{"container_name":"c"}`)
	if got := GetToolParam(args, "nonexistent"); got != "" {
		t.Errorf("GetToolParam(missing key) = %q, want empty", got)
	}
}

func TestGetToolParam_nonString(t *testing.T) {
	args := json.RawMessage(`{"port":8080}`)
	if got := GetToolParam(args, "port"); got != "" {
		t.Errorf("GetToolParam(int value) = %q, want empty", got)
	}
}

func TestGetToolParam_null(t *testing.T) {
	args := json.RawMessage(`{"name":null}`)
	if got := GetToolParam(args, "name"); got != "" {
		t.Errorf("GetToolParam(null) = %q, want empty", got)
	}
}

func TestGetToolParam_emptyObject(t *testing.T) {
	args := json.RawMessage(`{}`)
	if got := GetToolParam(args, "any"); got != "" {
		t.Errorf("GetToolParam(empty object) = %q, want empty", got)
	}
}

func TestGetToolParam_partialJSON(t *testing.T) {
	// Streaming scenario: JSON is not yet complete
	args := json.RawMessage(`{"container_name":"streamed-val`)
	got := GetToolParam(args, "container_name")
	if got != "streamed-val" {
		t.Errorf("GetToolParam(partial JSON) = %q, want streamed-val", got)
	}
}

func TestGetToolParam_emptyValue(t *testing.T) {
	args := json.RawMessage(`{"container_name":""}`)
	if got := GetToolParam(args, "container_name"); got != "" {
		t.Errorf("GetToolParam(empty string) = %q, want empty", got)
	}
}
