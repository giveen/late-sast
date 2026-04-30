//go:build cbm_embedded

package main

import _ "embed"

//go:embed embedded/codebase-memory-mcp
var cbmBinaryData []byte
