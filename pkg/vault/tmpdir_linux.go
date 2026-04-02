//go:build linux

package vault

import (
	"fmt"
	"os"
)

// SecureTmpDir creates a temporary directory in /dev/shm (RAM-backed) on Linux.
// Falls back to os.TempDir() if /dev/shm is not available.
func SecureTmpDir() (string, error) {
	const shmDir = "/dev/shm"

	if info, err := os.Stat(shmDir); err == nil && info.IsDir() {
		dir, err := os.MkdirTemp(shmDir, "locksmith-*")
		if err != nil {
			return "", fmt.Errorf("create tmpdir in %s: %w", shmDir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directory needs 0700 for owner-only access
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("chmod tmpdir: %w", err)
		}
		return dir, nil
	}

	return fallbackTmpDir()
}

func fallbackTmpDir() (string, error) {
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
