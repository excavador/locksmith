package gpgsmith

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/excavador/locksmith/pkg/daemon"
)

func TestEnsureDaemon_NoopWhenAlreadyRunning(t *testing.T) {
	dir := withPrivateRuntimeDir(t)

	// Pre-create a live listener at the canonical socket path. This
	// simulates a daemon that is already running — EnsureDaemon should
	// NOT try to spawn a new one.
	sock, err := daemon.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if got, want := filepath.Dir(sock), filepath.Join(dir, "gpgsmith"); got != want {
		t.Fatalf("socket path escaped runtime dir: %s", sock)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := EnsureDaemon(ctx, 500*time.Millisecond); err != nil {
		t.Errorf("expected EnsureDaemon to be a no-op when daemon is reachable, got %v", err)
	}
}

func TestEnsureDaemon_FailsWhenSpawnCannotBind(t *testing.T) {
	// This test verifies the wait-and-timeout branch of EnsureDaemon
	// without actually spawning a real gpgsmith binary. We give the
	// test a private runtime dir with no socket, so EnsureDaemon will
	// attempt to exec the current test binary as a daemon. The test
	// binary doesn't implement `daemon start --foreground`, so it will
	// exit almost immediately and the socket will never appear, which
	// is precisely the timeout path we want to exercise.
	if testing.Short() {
		t.Skip("skipping spawn timeout test in -short mode")
	}

	withPrivateRuntimeDir(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := EnsureDaemon(ctx, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected EnsureDaemon to fail when spawned child cannot bind socket")
	}
}
