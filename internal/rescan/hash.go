package rescan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
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
