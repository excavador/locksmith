package gpgsmith

import (
	"testing"
)

// withIsolatedLockDir points lock-file/temp-file lookups at a fresh temp
// dir for the duration of the test. In the post-flock daemon era there is
// no file-backed vault lock to isolate, but tests still benefit from a
// pristine XDG_RUNTIME_DIR / TMPDIR so ephemeral paths do not collide.
func withIsolatedLockDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("TMPDIR", dir)
	return dir
}
