//go:build !linux

package vault

import (
	"fmt"
	"os"
)

// SecureTmpDir creates a temporary directory using os.TempDir() on non-Linux systems.
func SecureTmpDir() (string, error) {
	dir, err := os.MkdirTemp("", "locksmith-*")
	if err != nil {
		return "", fmt.Errorf("create tmpdir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directory needs 0700 for owner-only access
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("chmod tmpdir: %w", err)
	}
	return dir, nil
}
