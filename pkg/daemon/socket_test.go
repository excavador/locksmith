package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSocketPathCreatesDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", tmp)
	t.Setenv("TMPDIR", tmp)

	p, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(p)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("parent is not a directory")
	}
}

func TestBindSocketFreshPath(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "gpgsmith.sock")

	ln, err := BindSocket(path)
	if err != nil {
		t.Fatalf("BindSocket: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("socket file missing: %v", err)
	}
}

func TestBindSocketStaleRecovery(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "gpgsmith.sock")

	// Plant a stale socket file (regular file that looks like a
	// leftover; BindSocket's detection relies on EADDRINUSE followed
	// by a failed dial). Simulate by binding-then-closing without
	// removing the inode.
	var lc net.ListenConfig
	ln1, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	// Close the listener but keep the socket inode around to simulate
	// a crashed daemon. net.Listen on Unix removes the inode on
	// Close() for *net.UnixListener by default, so we have to unlink
	// that behavior by recreating the file ourselves.
	_ = ln1.Close()
	// Create an empty regular file at the socket path to simulate a
	// leftover inode. A subsequent Listen will get EADDRINUSE, then
	// Dial will fail with ECONNREFUSED or similar — either way
	// BindSocket should recover.
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create leftover: %v", err)
	}
	_ = f.Close()

	ln2, err := BindSocket(path)
	if err != nil {
		t.Fatalf("BindSocket after stale: %v", err)
	}
	defer func() { _ = ln2.Close() }()
}

func TestBindSocketAlreadyRunning(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "gpgsmith.sock")

	ln, err := BindSocket(path)
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, err = BindSocket(path)
	if err == nil {
		t.Fatal("expected error on double bind")
	}
	if !IsAlreadyRunning(err) {
		t.Errorf("expected AlreadyRunningError, got %v", err)
	}
}
