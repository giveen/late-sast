package rescan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// HashFile returns the SHA-256 hex digest of a file's content.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashBytes returns the SHA-256 hex digest of a byte slice.
func HashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TransformKey returns a deterministic cache key for a specific (transform, version,
// input) triple.  The three components are joined with NUL bytes before hashing so
// that the concatenation is unambiguous.
func TransformKey(transformName, transformVersionHash, inputHash string) string {
	raw := transformName + "\x00" + transformVersionHash + "\x00" + inputHash
	return HashBytes([]byte(raw))
}

// FindingID returns a stable identity key for a security finding.
// The key is derived from CWE, the normalized location (lowercased), and the
// normalized title (lowercased) so it remains stable across runs even when the
// LLM produces minor textual variations in non-key fields.
func FindingID(cwe int, location, title string) string {
	raw := fmt.Sprintf("%d\x00%s\x00%s",
		cwe,
		strings.ToLower(strings.TrimSpace(location)),
		strings.ToLower(strings.TrimSpace(title)),
	)
	return HashBytes([]byte(raw))
}
