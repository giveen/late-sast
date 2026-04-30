//go:build !cbm_embedded

package main

// cbmBinaryData is nil when built without -tags cbm_embedded.
// ensureCBM falls back to downloading from GitHub Releases at runtime.
var cbmBinaryData []byte
